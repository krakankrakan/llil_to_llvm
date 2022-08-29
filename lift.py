from binaryninja import *
import llvmlite.ir as ll
import llil_to_llvm.addr_map as addr_map

bn_operation_to_builder_func_map = {
    binaryninja.LowLevelILOperation.LLIL_ADD : "add",
    binaryninja.LowLevelILOperation.LLIL_SUB : "sub",
    binaryninja.LowLevelILOperation.LLIL_OR  :  "or_",
    binaryninja.LowLevelILOperation.LLIL_XOR : "xor",
    binaryninja.LowLevelILOperation.LLIL_AND : "and_",
    binaryninja.LowLevelILOperation.LLIL_LSL : "shl",
    binaryninja.LowLevelILOperation.LLIL_LSR : "lshr"
}

bn_operation_cmp_map = {
    binaryninja.LowLevelILOperation.LLIL_CMP_E   : ("u", "=="),
    binaryninja.LowLevelILOperation.LLIL_CMP_NE  : ("u", "!="),
    binaryninja.LowLevelILOperation.LLIL_CMP_SGE : ("s", ">="),
    binaryninja.LowLevelILOperation.LLIL_CMP_SGT : ("s", ">"),
    binaryninja.LowLevelILOperation.LLIL_CMP_SLE : ("s", "<="),
    binaryninja.LowLevelILOperation.LLIL_CMP_SLT : ("s", "<"),
    binaryninja.LowLevelILOperation.LLIL_CMP_UGE : ("u", ">="),
    binaryninja.LowLevelILOperation.LLIL_CMP_UGT : ("u", ">"),
    binaryninja.LowLevelILOperation.LLIL_CMP_ULE : ("u", "<="),
    binaryninja.LowLevelILOperation.LLIL_CMP_ULT : ("u", "<")
}

def call_method(o, method, arg1, arg2):
    return getattr(o, method)(arg1, arg2)

def bn_type_to_llvm(bn_type):

    #print(bn_type)

    if (bn_type == None):
        return ll.VoidType()

    if (bn_type.type_class == TypeClass.IntegerTypeClass):
        return ll.IntType(bn_type.width * 8)

    if (bn_type.type_class == TypeClass.PointerTypeClass):
        return ll.PointerType(ll.IntType(bn_type.width * 8), 0)

    if (bn_type.type_class == TypeClass.VoidTypeClass):
        return ll.VoidType()

    return None

def bn_function_type_to_llvm(func):
    param_types = []

    #print("Params")

    for param in func.parameter_vars:
        param_types.append(bn_type_to_llvm(param.type))

    #print("Return type")

    return ll.FunctionType(
        bn_type_to_llvm(func.return_type),
        param_types
    )

def size_to_llvm_type(size):
    if size != 0:
        return ll.IntType(size * 8)

class Lifter:
    bv = None
    br = None
    builder = None
    module = None
    lifter_get_mapped_addr_func = None
    
    def __init__(self, bv):
        self.bv = bv
        self.br = BinaryReader(bv, bv.endianness)
        self.module = ll.Module()
        self.builder = ll.IRBuilder()
        self.insert_lifter_get_mapped_addr_func = addr_map.insert_lifter_get_mapped_addr_func(self.module)

    def create_data_global(self):
        global_data_segments = []

        # Get all global data segments
        for segment in self.bv.segments:
            if ((segment.readable and not segment.executable) or segment.writable):
                global_data_segments.append(segment)

        for segment in global_data_segments:
            #print(segment)

            segment_length = segment.data_length;

            self.br.seek(segment.start)

            #print(hex(segment.start))
            #print(hex(self.br.offset))
            #print(hex(segment_length))

            segment_data = self.br.read(segment_length)

            if segment_data is not None:
                ll_segment_data_type = ll.ArrayType(ll.IntType(8), segment_length)

                data_constant = ll.Constant(ll_segment_data_type, bytearray(segment_data))
                data_global = ll.GlobalVariable(self.module, ll_segment_data_type, "segment_" + hex(segment.start))
                data_global.initializer = data_constant
            else:
                print("segment_data is none!")

    def append_reg(self, reg_name, reg_to_alloca):
        # LLIL register is an architecture register
        if reg_name not in reg_to_alloca:
            if reg_name in self.bv.arch.regs:

                # Check if it is a partial register only
                reg_size = 8
                full_reg = reg_name

                if full_reg not in reg_to_alloca:
                    if self.check_is_partial_reg_arm(reg_name):
                        full_reg = self.get_full_reg_arm(reg_name)
                        reg_size = self.get_reg_size_arm(full_reg)

                    #alloca = self.builder.alloca(
                    #    size_to_llvm_type(
                    #        reg_size
                    #    ),
                    #    name = full_reg
                    #)
                    reg_to_alloca[full_reg] = None# alloca

            # LLIL register is a variable/no architecture register
            else:
                #alloca = self.builder.alloca(
                #    size_to_llvm_type(8),
                #    name = reg_name
                #) 
                reg_to_alloca[reg_name] = None #alloca
        
        return reg_to_alloca

    def generate_reg_allocas_recursive(self, llil_inst, reg_to_alloca):
        #print(llil_inst)

        if type(llil_inst) == binaryninja.lowlevelil.ILRegister:
            reg_name = llil_inst.name
            reg_to_alloca = self.append_reg(reg_name, reg_to_alloca)

            return reg_to_alloca

        #print(llil_inst.operation)

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_REG:
            reg_name = llil_inst.operands[0].name

            # LLIL register is an architecture register
            reg_to_alloca = self.append_reg(reg_name, reg_to_alloca)

        else:
            for operand in llil_inst.operands:
                if issubclass(type(operand), binaryninja.lowlevelil.LowLevelILInstruction) or type(operand) == binaryninja.lowlevelil.ILRegister:
                    reg_to_alloca = self.generate_reg_allocas_recursive(operand, reg_to_alloca)

        return reg_to_alloca

    def generate_reg_allocas(self, bn_func):
        reg_to_alloca = {}

        # Append ARM function parameter registers
        for reg in ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]:
            reg_to_alloca = self.append_reg(reg, reg_to_alloca)

        for llil_inst in bn_func.llil_instructions:
            #print("generate_reg_allocas_recursive")
            reg_to_alloca = self.generate_reg_allocas_recursive(llil_inst, reg_to_alloca)

        for reg in reg_to_alloca:
            reg_size = self.get_reg_size_arm(reg)
            alloca = self.builder.alloca(
                        size_to_llvm_type(
                            reg_size
                        ),
                        name = reg
                    )
            reg_to_alloca[reg] = alloca

        return reg_to_alloca

    # ARM Aarch64-specific register handling
    def check_is_partial_reg_arm(self, reg_name):
        if reg_name[0] == "w":
            return True
        return False

    def get_full_reg_arm(self, reg_name):
        return "x" + reg_name[1:]

    def get_reg_size_arm(self, reg_name):
        if reg_name[0] == "x":
            return 8
        if reg_name[0] == "w":
            return 4
        else:
            return 8

    # Casts a register pointer to the needed value.
    def handle_reg_ptr_arm(self, reg_name, reg_to_alloca):
        if self.check_is_partial_reg_arm(reg_name):
            full_reg = self.get_full_reg_arm(reg_name)

            casted_reg = self.builder.bitcast(
                reg_to_alloca[full_reg],
                ll.PointerType(size_to_llvm_type(self.get_reg_size_arm(reg_name)), 0)
            )

            return casted_reg
        else:
            return reg_to_alloca[reg_name]

    # Casts an LLVM Value to the size needed by a register to hold the value.
    def handle_reg_assign_arm(self, reg_name, value, reg_to_alloca):
        reg_ptr = self.handle_reg_ptr_arm(reg_name, reg_to_alloca)

        self.builder.store(
            value,
            reg_ptr
        )

    def handle_reg_load_arm(self, reg_name, reg_to_alloca):
        if self.check_is_partial_reg_arm(reg_name):
            full_reg = self.get_full_reg_arm(reg_name)

            loaded_reg = self.builder.load(
                reg_to_alloca[full_reg]
            )

            return self.builder.bitcast(
                loaded_reg,
                size_to_llvm_type(self.get_reg_size_arm(reg_name))
            )
        else:
            loaded_reg = self.builder.load(
                reg_to_alloca[reg_name]
            )

            return loaded_reg

    def get_return_register_arm(self):
        return "x0"

    def get_arg_registers_arm(self, count, reg_to_alloca):
        param_regs = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]

        if count == 0:
            return []
        elif count <= 8:
            loaded_regs = []

            for param_reg in param_regs[0:count]:
                loaded_regs.append(self.handle_reg_load_arm(param_reg, reg_to_alloca))

            return loaded_regs
        else:
            raise Exception("Too many function arguments!")

    def create_function_declaration(self, bn_func):
        print("Created function declaration for: " + bn_func.name)

        func_type = bn_function_type_to_llvm(bn_func)

        print(func_type)

        func = ll.Function(self.module, func_type, bn_func.name)

        return func

    def visit_function(self, bn_func, func, addr_to_func):
        #print(type(bn_func))

        bb_entry = func.append_basic_block()
        self.builder.position_at_end(bb_entry)

        # Stack allocation for the registers (which are actually used)
        reg_to_alloca = self.generate_reg_allocas(bn_func)

        print("reg_to_alloca dict:")
        print(reg_to_alloca.keys())

        # Copy the function arguments in the correct registers
        for i in range(0, len(func.args)):
            reg = list(reg_to_alloca.values())[i]
            func_arg = func.args[i]

            if func.args[i].type != ll.IntType(64):
                func_arg = self.builder.bitcast(func_arg, ll.IntType(64))

            self.builder.store(func_arg, reg)

        bb_list = []
        bb_seen = []
        bb_dict = {} # Maps a LLIL address to a BasicBlock
        bb_reverse_dict = {} # Maps a BasicBlock address to a LLIL address
        bb_successors = {}
        bb_check_values = {}

        if len(list(bn_func.llil_instructions)) > 0:
            bb_list.append(0)
            bb_dict[0] = bb_entry
        else:
            return

        while len(bb_list) > 0:
            bb = bb_list[0]
            del bb_list[0]

            # Don't visit BBs twice
            if bb in bb_seen:
                continue
            bb_seen.append(bb)

            llvm_bb = None

            if bb != 0:
                llvm_bb = func.append_basic_block()
                self.builder.position_at_end(llvm_bb)
                bb_dict[bb] = llvm_bb
            else:
                llvm_bb = bb_entry

            bb_reverse_dict[llvm_bb] = bb

            print("LLIL address: " + str(bb))
            print("BB name: " + str(llvm_bb.name))

            idx = 0
            for i in bn_func.llil_instructions:
                if (idx >= bb):

                    if self.is_jump(i):
                        print("Visit jump instruction:")
                        print(i)

                        jump_info = self.visit_jump_instruction(i, func, 0, reg_to_alloca)

                        # Store the BB successors
                        next_bbs = jump_info[0]
                        print("Successors: " + str(next_bbs))
                        if next_bbs is not None:
                            for next_bb in next_bbs:
                                if next_bb not in bb_seen:
                                    bb_list.append(next_bb)

                        bb_successors[llvm_bb] = next_bbs

                        bb_check_values[llvm_bb] = jump_info[1]

                        break
                    else:
                        print("Visit instruction:")
                        print(i)

                        self.visit_instruction(i, func, 0, reg_to_alloca, addr_to_func)

                idx += 1
            
            print("Lifted BB at LLIL address: " + str(bb))

        for bb, successors in bb_successors.items():
            #print("bb:")
            #print(bb)
            #print(bb.function.name)
            #print("LLIL address: " + str(bb_reverse_dict[bb]))
            #print("Successors: " + str(successors))

            # RET
            if len(successors) == 0:
                continue
            
            # GOTO
            elif len(successors) == 1:
                successor = bb_dict[successors[0]]
                #self.builder = ll.IRBuilder(bb)
                self.builder.position_at_end(bb)
                self.builder.branch(successor)
            
            # IF
            else:
                successor_t = bb_dict[successors[0]]
                successor_f = bb_dict[successors[1]]
                #self.builder = ll.IRBuilder(bb)
                self.builder.position_at_end(bb)
                self.builder.cbranch(bb_check_values[bb], successor_t, successor_f)

            #for bb in func.blocks:
            #    for inst in bb.instructions:
            #        print("Operands:")
            #        for operand in inst.operands:
            #            print(operand)
            #        print("Instruction:")
            #        print(inst.opname)
            #        print(inst)


        print(func)

    #def reg_to_llvm(self, reg_name):
    #    if self.check_is_partial_reg_arm(reg_name):
    #        return self.get_full_reg_arm(reg_name)
    #    else:
    #        return reg_name

    def is_jump(self, llil_inst):
        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_GOTO or llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_IF or llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_NORET or llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_RET or llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_TAILCALL:
            return True
        else:
            return False

    def visit_jump_instruction(self, llil_inst, func, level, reg_to_alloca, size=8):
        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_GOTO:
            return ([llil_inst.operands[0]], None)

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_IF:
            # Visit the condition
            cmp_value = self.visit_instruction(llil_inst.operands[0], func, 1, reg_to_alloca, size)[1]
            return ([llil_inst.operands[1], llil_inst.operands[2]], cmp_value) # T, F

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_NORET:
            if (func.ftype.return_type == ll.VoidType()):
                self.builder.ret_void()
            else:
                self.builder.ret(
                    ll.Constant(func.ftype.return_type, 0)
                )

            return ([], None)

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_RET:
            if (func.ftype.return_type == ll.VoidType()):
                self.builder.ret_void()
            else:
                return_reg = self.get_return_register_arm()

                loaded_reg = self.handle_reg_load_arm(return_reg, reg_to_alloca)

                # Only cast if really needed.
                if loaded_reg.type != func.ftype.return_type:
                    casted_ret_cal = self.builder.bitcast(
                        loaded_reg,
                        func.ftype.return_type
                    )
                    self.builder.ret(casted_ret_cal)
                else:
                    self.builder.ret(loaded_reg)
            
            return ([], None)

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_TAILCALL:
            return_value = self.visit_instruction(llil_inst, func, 0, reg_to_alloca, size)[1]
            print(return_value)
            if (func.ftype.return_type != ll.VoidType()):
                casted_ret_cal = self.builder.bitcast(
                    return_value,
                    func.ftype.return_type
                )
                self.builder.ret(casted_ret_cal)
            else:
                self.builder.ret_void()

            return ([], None)

    def visit_instruction(self, llil_inst, func, level, reg_to_alloca, addr_to_func, size=8):
        #print((level + 1) * "   " + "visited:" + str(llil_inst.operation))
        #print(level * "   " + "operands: " + str(llil_inst.operands))

        #print(llil_inst)
        #print(type(llil_inst))

        #for operand in llil_inst.operands:
        #    if issubclass(type(operand), binaryninja.lowlevelil.LowLevelILInstruction):
        #        self.visit_instruction(operand, level+1, reg_to_alloca)
        #    else:
        #        #print((level + 1) * "   " + "non-visited:" + str(type(operand)))
        #        pass

        # Some instructions are easy to lift, like add, sub, and, etc..
        if llil_inst.operation in bn_operation_to_builder_func_map:
            a = self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, size)
            b = self.visit_instruction(llil_inst.operands[1], func, level+1, reg_to_alloca, addr_to_func, size)

            # TODO: Is the correct size returned?
            return (
                a[0],
                call_method(
                    self.builder,
                    bn_operation_to_builder_func_map[llil_inst.operation],
                    a[1],
                    b[1]
            ))

        # List cmp instructions
        if llil_inst.operation in bn_operation_cmp_map:
            a = self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, size)
            b = self.visit_instruction(llil_inst.operands[1], func, level+1, reg_to_alloca, addr_to_func, size)

            cmp_info = bn_operation_cmp_map[llil_inst.operation]

            if cmp_info[0] == "u":
                return (
                    a[0],
                    self.builder.icmp_unsigned(
                        cmp_info[1],
                        a[1],
                        b[1]
                    )
                )

            elif cmp_info[0] == "s":
                return (
                    a[0],
                    self.builder.icmp_signed(
                        cmp_info[1],
                        a[1],
                        b[1]
                    )
                )
            
            else:
                raise Exception("CMP sign not detected")

        # Special handling for all other instructions
        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_LOAD:
            loaded = None

            loaded_value = self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, size)
            if not issubclass(type(loaded_value[1].type), ll.PointerType):
                loaded = self.builder.inttoptr(
                    loaded_value[1],
                    ll.PointerType(loaded_value[1].type)
                    )
            else:
                loaded = loaded_value[1]

            return (
                loaded_value[0],
                self.builder.load(
                    loaded
            ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_STORE:

            if issubclass(type(llil_inst.operands[0]), binaryninja.lowlevelil.LowLevelILReg):
                reg_name = llil_inst.operands[0].operands[0].name

                store_value = self.visit_instruction(llil_inst.operands[1], func, level+1, reg_to_alloca, addr_to_func, self.get_reg_size_arm(reg_name))

                return (
                    0,
                    self.builder.store(
                        store_value[1],
                        self.builder.inttoptr(
                            self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func)[1],
                            ll.PointerType(size_to_llvm_type(store_value[0]), 0)
                        )
                ))
            else:
                store_location = self.visit_instruction(llil_inst.operands[1], func, level+1, reg_to_alloca, addr_to_func, size)

                store_value = self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, store_location[0])
                casted_store_value = self.builder.inttoptr(
                    store_value[1],
                    ll.PointerType(size_to_llvm_type(store_value[0]), 0)
                )

                return (
                    0,
                    self.builder.store(
                        store_location[1],
                        casted_store_value
                    )
                )

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_NOT:
            return (
                size,
                self.builder.not_(
                    self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, size)[1]
            ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_SX:
            return (
                size,
                self.builder.sext(
                    self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, size)[1],
                    size_to_llvm_type(size)
            ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_LOW_PART:
            return (
                int(size / 2),
                self.builder.trunc(
                    self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, size)[1],
                    size_to_llvm_type(int(size / 2))
            ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_SET_REG:
            reg_name = llil_inst.operands[0].name

            value = self.visit_instruction(llil_inst.operands[1], func, level+1, reg_to_alloca, addr_to_func, self.get_reg_size_arm(reg_name))[1]

            self.handle_reg_assign_arm(
                reg_name,
                value,
                reg_to_alloca
            )

            return None

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_REG:
            reg_name = llil_inst.operands[0].name

            if self.get_reg_size_arm(reg_name) != size:
                return (
                    size,
                    self.builder.bitcast(
                        self.handle_reg_load_arm(
                            reg_name,
                            reg_to_alloca
                        ),
                        size_to_llvm_type(size)
                ))
            else:
                return (
                    self.get_reg_size_arm(reg_name),
                    self.handle_reg_load_arm(
                        reg_name,
                        reg_to_alloca
                ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_CONST or llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_CONST_PTR:
            return (
                size, 
                ll.Constant(size_to_llvm_type(size),
                    llil_inst.operands[0]
            ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_CALL or llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_TAILCALL:

            # If the argument is a hardcoded address, we can simply look up the call target.
            if llil_inst.operands[0].operation == binaryninja.LowLevelILOperation.LLIL_CONST or llil_inst.operands[0].operation == binaryninja.LowLevelILOperation.LLIL_CONST_PTR:

                callee_func = addr_to_func[llil_inst.operands[0].operands[0]]

                #print(callee_func.ftype)
                #print(callee_func.args)
                #print(len(callee_func.args))

                args = self.get_arg_registers_arm(len(callee_func.args), reg_to_alloca)

                # Cast args as needed
                for i in range(0, len(args)):
                    if callee_func.args[i].type != args[i].type:
                        args[i] = self.builder.bitcast(
                            args[i],
                            callee_func.args[i].type
                        )

                return_value = self.builder.call(callee_func, args)

                if (func.ftype.return_type != ll.VoidType()):
                    return_value = self.builder.bitcast(
                        return_value,
                        ll.IntType(64)
                    )
                    
                    return (
                        self.get_reg_size_arm(self.get_return_register_arm()),
                        self.handle_reg_assign_arm(self.get_return_register_arm(), return_value, reg_to_alloca)
                    )

            # Otherwise, we have to look up the call target during runtime.
            else:
                #raise Exception("Cannot get call target!")

                call_target = self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, size)

                #if call_target.type != ll.IntType(64):
                #    call_target = self.builder.bitcast(
                #        call_target,
                #        ll.IntType(64)
                #    )

                new_addr = self.builder.call(self.insert_lifter_get_mapped_addr_func, [ call_target[1] ])

                # We assume that the callee has 8 parameters.
                args = self.get_arg_registers_arm(8, reg_to_alloca)
                call_target_func_type =  ll.FunctionType(ll.IntType(64), [ll.IntType(64)] * 8)
                call_target_casted = self.builder.inttoptr(new_addr, call_target_func_type)

                return_value = self.builder.call(call_target_casted, args)

                self.handle_reg_assign_arm(self.get_return_register_arm(), return_value, reg_to_alloca)

                return (
                        self.get_reg_size_arm(self.get_return_register_arm()),
                        self.handle_reg_load_arm(self.get_return_register_arm(), reg_to_alloca)
                    )

        print((level + 1) * "   " + "visited:" + str(llil_inst.operation))

    def dump(self):
        module_str = self.module.__str__() + "\n" + addr_map.ir_map_code

        with open("/Users/krakan/out.txt", "w+") as f:
            f.write(module_str)

    def lift(self):
        self.create_data_global()

        functions = []

        for fn in self.bv.functions:
            func = self.create_function_declaration(fn)
            functions.append((fn, func))

        addr_to_func = {}
        for fn in functions:
            fn_start = fn[0].address_ranges[0].start
            addr_to_func[fn_start] = fn[1]

            #addr_map.add_addr_map_function_entry(self.module, fn_start, fn[1])

        for fn in functions:
            print("FUNCTION: " + str(fn[0].name))
            self.visit_function(fn[0], fn[1], addr_to_func)

        addr_map.create_addr_map(self.module)

        #print(self.module)
        self.dump()