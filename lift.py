from binaryninja import *
import llvmlite.ir as ll
import llil_to_llvm.addr_map as addr_map
import llil_to_llvm.arch as arch
import llil_to_llvm.util as util

bn_operation_to_builder_func_map = {
    binaryninja.LowLevelILOperation.LLIL_ADD : "add",
    binaryninja.LowLevelILOperation.LLIL_SUB : "sub",
    binaryninja.LowLevelILOperation.LLIL_OR  :  "or_",
    binaryninja.LowLevelILOperation.LLIL_XOR : "xor",
    binaryninja.LowLevelILOperation.LLIL_AND : "and_",
    binaryninja.LowLevelILOperation.LLIL_LSL : "shl",
    binaryninja.LowLevelILOperation.LLIL_LSR : "lshr",
    binaryninja.LowLevelILOperation.LLIL_ASR : "ashr",
    binaryninja.LowLevelILOperation.LLIL_DIVS    : "sdiv",
    binaryninja.LowLevelILOperation.LLIL_DIVS_DP : "sdiv",
    binaryninja.LowLevelILOperation.LLIL_DIVU    : "udiv",
    binaryninja.LowLevelILOperation.LLIL_DIVU_DP : "udiv"
}

bn_mul_operation_to_builder_func_map = {
    binaryninja.LowLevelILOperation.LLIL_MUL     : "umul_with_overflow",
    binaryninja.LowLevelILOperation.LLIL_MULS_DP : "smul_with_overflow",
    binaryninja.LowLevelILOperation.LLIL_MULU_DP : "umul_with_overflow"
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

    if bn_type == None:
        return ll.VoidType()

    if bn_type.type_class == TypeClass.IntegerTypeClass:
        return ll.IntType(bn_type.width * 8)

    if bn_type.type_class == TypeClass.PointerTypeClass:
        return ll.PointerType(ll.IntType(bn_type.width * 8), 0)

    if bn_type.type_class == TypeClass.VoidTypeClass:
        return ll.VoidType()

    if bn_type.type_class == TypeClass.NamedTypeReferenceClass:
        if bn_type.name == "off64_t" or  bn_type.name == "size_t" or bn_type.name == "ssize_t":
            return ll.IntType(64)

    if bn_type.type_class == TypeClass.StructureTypeClass:
        struct_fields = []
        for field in bn_type.members():
            struct_fields.append(bn_type_to_llvm(field))
        return ll.LiteralStructType(struct_fields, packed=bn_type.packed())

    if bn_type.type_class == TypeClass.EnumerationTypeClass:
        return ll.IntType(bn_type.width * 8)

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

def size_to_llvm_float_type(size):
    if size != 0:
        return ll.FloatType()

class Lifter:
    bv = None
    br = None
    builder = None
    module = None
    lifter_get_mapped_addr_func = None
    arch_funcs = None
    sp = None
    
    def __init__(self, bv):
        self.bv = bv
        self.br = BinaryReader(bv, bv.endianness)
        self.module = ll.Module()
        self.builder = ll.IRBuilder()
        self.insert_lifter_get_mapped_addr_func = addr_map.insert_lifter_get_mapped_addr_func(self.module)

        if bv.arch == binaryninja.architecture.Architecture["aarch64"]:
            self.arch_funcs = arch.ARMFunctions(self.builder)
        elif bv.arch == binaryninja.architecture.Architecture["x86_64"]:
            self.arch_funcs = arch.x86Functions(self.builder)
        elif bv.arch == binaryninja.architecture.Architecture["riscv"]:
            self.arch_funcs = arch.RISCVFunctions(self.builder)
        else:
            raise Exception("Architecture not supported by LLIL to LLVM lifter!")

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

                # Also add address mapping
                addr_map.add_addr_map_data_section(segment.start, segment_length, data_global)
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
                    if self.arch_funcs.check_is_partial_reg(reg_name):
                        full_reg = self.arch_funcs.get_full_reg(reg_name)
                        reg_size = self.arch_funcs.get_reg_size(full_reg)

                    reg_to_alloca[full_reg] = None

            # LLIL register is a variable/no architecture register
            else:
                reg_to_alloca[reg_name] = None
        
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
        sp_reg = self.arch_funcs.get_stack_register()

        # Append ARM function parameter registers
        for reg in self.arch_funcs.param_regs:
            reg_to_alloca = self.append_reg(reg, reg_to_alloca)

        for llil_inst in bn_func.llil_instructions:
            #print("generate_reg_allocas_recursive")
            reg_to_alloca = self.generate_reg_allocas_recursive(llil_inst, reg_to_alloca)

        reg_to_alloca[sp_reg] = self.sp

        for reg in reg_to_alloca:
            # Use the global variable for the stack register
            if reg == sp_reg:
                continue

            #print(reg)
            reg_size = self.arch_funcs.get_reg_size(reg)
            #print(reg_size)

            alloca = self.builder.alloca(
                        size_to_llvm_type(
                            reg_size
                        ),
                        name = reg
                        )
            reg_to_alloca[reg] = alloca

        return reg_to_alloca

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
        print(reg_to_alloca)

        # Push a fake return address on the stack
        sp_reg = self.arch_funcs.get_stack_register()
        sp_ptr = self.arch_funcs.handle_reg_load(
                                    sp_reg,
                                    reg_to_alloca
                            )
        self.builder.store(
            ll.Constant(ll.IntType(64), 0x4141414141414141),
            util.cast_to_type(self.builder, sp_ptr, ll.PointerType(ll.IntType(64), 0))
        )
        new_sp_ptr = self.builder.add(sp_ptr, ll.Constant(ll.IntType(64), 8))
        self.arch_funcs.handle_reg_assign(
            sp_reg,
            new_sp_ptr,
            reg_to_alloca
        )

        # Copy the function arguments in the correct registers
        for i in range(0, len(func.args)):
            reg = list(reg_to_alloca.values())[i]
            func_arg = func.args[i]

            if func.args[i].type != ll.IntType(64):
                #func_arg = self.builder.bitcast(func_arg, ll.IntType(64))
                func_arg = util.cast_to_type(self.builder, func_arg, ll.IntType(64))

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
                    #ll.Constant(func.ftype.return_type, 0)
                    util.get_null(func.ftype.return_type)
                )

            return ([], None)

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_RET:
            if (func.ftype.return_type == ll.VoidType()):
                self.builder.ret_void()
            else:
                return_reg = self.arch_funcs.get_return_register()

                loaded_reg = self.arch_funcs.handle_reg_load(return_reg, reg_to_alloca)

                # Only cast if really needed.
                if loaded_reg.type != func.ftype.return_type:
                    #casted_ret_cal = self.builder.bitcast(
                    #    loaded_reg,
                    #    func.ftype.return_type
                    #)
                    casted_ret_cal = util.cast_to_type(
                        self.builder,
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
                #casted_ret_cal = self.builder.bitcast(
                #    return_value,
                #    func.ftype.return_type
                #)
                casted_ret_cal = util.cast_to_type(
                    self.builder,
                    return_value,
                    func.ftype.return_type
                )
                self.builder.ret(casted_ret_cal)
            else:
                self.builder.ret_void()

            return ([], None)

    def visit_instruction(self, llil_inst, func, level, reg_to_alloca, addr_to_func, size=8):

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
                )
            )

        # Multiplication, division, with overflow. Return the resulting value and the carry (which will be ignored).
        if llil_inst.operation in bn_mul_operation_to_builder_func_map:
            a = self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, size)
            b = self.visit_instruction(llil_inst.operands[1], func, level+1, reg_to_alloca, addr_to_func, size)

            # TODO: Is the correct size returned?
            return (
                a[0],
                self.builder.extract_value(
                    call_method(
                        self.builder,
                        bn_mul_operation_to_builder_func_map[llil_inst.operation],
                        a[1],
                        b[1]
                    ),
                    0
                )
            )

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
            loaded_value = self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, 8)

            loaded_ptr = self.builder.call(self.insert_lifter_get_mapped_addr_func, [ util.cast_to_type(self.builder, loaded_value[1], ll.IntType(64)) ])
            loaded_ptr = self.builder.inttoptr(
                loaded_ptr,
                ll.PointerType(ll.IntType(64))
            )
            loaded_ptr = util.cast_to_type(self.builder, loaded_ptr, ll.PointerType(ll.IntType(size * 8)))

            return (
                loaded_value[0],
                self.builder.load(
                    loaded_ptr
            ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_STORE:
            store_value = None

            if issubclass(type(llil_inst.operands[0]), binaryninja.lowlevelil.LowLevelILReg):
                reg_name = llil_inst.operands[0].operands[0].name

                store_value = self.visit_instruction(llil_inst.operands[1], func, level+1, reg_to_alloca, addr_to_func, self.arch_funcs.get_reg_size(reg_name))
            else:
                store_value = self.visit_instruction(llil_inst.operands[1], func, level+1, reg_to_alloca, addr_to_func, size)

            store_ptr = self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func)
            new_store_ptr = self.builder.call(self.insert_lifter_get_mapped_addr_func, [ store_ptr[1] ])
            new_store_ptr = self.builder.inttoptr(
                new_store_ptr,
                ll.PointerType(size_to_llvm_type(store_value[0]), 0)
            )

            return (
                0,
                self.builder.store(
                    store_value[1],
                    new_store_ptr
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

            value = self.visit_instruction(llil_inst.operands[1], func, level+1, reg_to_alloca, addr_to_func, self.arch_funcs.get_reg_size(reg_name))[1]

            self.arch_funcs.handle_reg_assign(
                reg_name,
                value,
                reg_to_alloca
            )

            return None

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_REG:
            reg_name = llil_inst.operands[0].name

            if self.arch_funcs.get_reg_size(reg_name) != size:
                return (
                    size,
                    util.cast_to_type(
                        self.builder,
                        self.arch_funcs.handle_reg_load(
                            reg_name,
                            reg_to_alloca
                        ),
                        size_to_llvm_type(size)
                ))
            else:
                return (
                    self.arch_funcs.get_reg_size(reg_name),
                    self.arch_funcs.handle_reg_load(
                        reg_name,
                        reg_to_alloca
                ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_CONST or llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_CONST_PTR:
            return (
                size, 
                ll.Constant(size_to_llvm_type(size),
                    llil_inst.operands[0]
            ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_PUSH:
            sp = self.arch_funcs.get_stack_register()
            sp_ptr = self.arch_funcs.handle_reg_load(
                                        sp,
                                        reg_to_alloca
                                )

            push_value = self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, size)
            self.builder.store(
                push_value[1],
                util.cast_to_type(self.builder, sp_ptr, ll.PointerType(ll.IntType(push_value[0] * 8), 0))
            )

            new_sp_ptr = self.builder.add(sp_ptr, ll.Constant(ll.IntType(64), push_value[0]))
            return (
                push_value[1],
                self.arch_funcs.handle_reg_assign(
                    sp,
                    new_sp_ptr,
                    reg_to_alloca
                )
            )

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_POP:
            sp = self.arch_funcs.get_stack_register()
            sp_ptr = self.arch_funcs.handle_reg_load(
                                        sp,
                                        reg_to_alloca
                                )

            pop_value = self.builder.load(
                util.cast_to_type(self.builder, sp_ptr, ll.PointerType(ll.IntType(size * 8), 0))
            )

            new_sp_ptr = self.builder.add(sp_ptr, ll.Constant(ll.IntType(64), 8))
            self.arch_funcs.handle_reg_assign(
                sp,
                new_sp_ptr,
                reg_to_alloca
            )

            return (
                size,
                pop_value
            )

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_CALL or llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_TAILCALL:

            # If the argument is a hardcoded address, we can simply look up the call target.
            if llil_inst.operands[0].operation == binaryninja.LowLevelILOperation.LLIL_CONST or llil_inst.operands[0].operation == binaryninja.LowLevelILOperation.LLIL_CONST_PTR:

                callee_func = addr_to_func[llil_inst.operands[0].operands[0]]

                #print(callee_func.ftype)
                #print(callee_func.args)
                #print(len(callee_func.args))

                args = self.arch_funcs.get_arg_registers(len(callee_func.args), reg_to_alloca)

                # Cast args as needed
                for i in range(0, len(args)):
                    if callee_func.args[i].type != args[i].type:
                        args[i] = util.cast_to_type(
                            self.builder,
                            args[i],
                            callee_func.args[i].type
                        )

                return_value = self.builder.call(callee_func, args)

                if (callee_func.ftype.return_type != ll.VoidType()):
                    return_value = util.cast_to_type(
                        self.builder,
                        return_value,
                        ll.IntType(64)
                    )
                    
                    return (
                        self.arch_funcs.get_reg_size(self.arch_funcs.get_return_register()),
                        self.arch_funcs.handle_reg_assign(self.arch_funcs.get_return_register(), return_value, reg_to_alloca)
                    )
                else:
                    return (
                        8,
                        ll.Constant(ll.IntType(64), 0)
                    )

            # Otherwise, we have to look up the call target during runtime.
            else:
                #raise Exception("Cannot get call target!")

                call_target = self.visit_instruction(llil_inst.operands[0], func, level+1, reg_to_alloca, addr_to_func, size)

                new_addr = self.builder.call(self.insert_lifter_get_mapped_addr_func, [ call_target[1] ])

                # We assume that the callee has 8 parameters.
                args = self.arch_funcs.get_arg_registers(8, reg_to_alloca)
                call_target_func_type =  ll.FunctionType(ll.IntType(64), [ll.IntType(64)] * 8)
                call_target_casted = self.builder.inttoptr(new_addr, ll.PointerType(call_target_func_type, 0))

                return_value = self.builder.call(call_target_casted, args)

                self.arch_funcs.handle_reg_assign(self.arch_funcs.get_return_register(), return_value, reg_to_alloca)

                return (
                        self.arch_funcs.get_reg_size(self.arch_funcs.get_return_register()),
                        self.arch_funcs.handle_reg_load(self.arch_funcs.get_return_register(), reg_to_alloca)
                    )

        # Floating-point instructions
        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_FLOAT_CONST:
            return (
                size, 
                ll.Constant(size_to_llvm_float_type(size),
                    llil_inst.operands[0]
            ))

        print("COULD NOT LIFT:" + str(llil_inst) + ", operation: " + str(llil_inst.operation) + ", type: " + str(type(llil_inst)))

    def create_stack(self):
        self.sp = ll.GlobalVariable(self.module, ll.IntType(64), name="stack")
        self.sp.linkage = 'external'
        self.sp.global_constant = False

    def dump(self):
        ir_map_code = addr_map.ir_map_code

        # Replace the declaration of "lifter_addr_map" in the IR code with the
        # correct size
        ir_map_code = ir_map_code.replace("[0 x i64]", "[" + str(len(addr_map.addr_map) * 3) + " x i64]")

        module_str = self.module.__str__() + "\n" + ir_map_code

        # Hack to replace the declaration of "lifter_get_mapped_addr" with
        # the definition provided in addr_map.py
        f_declaration = "declare i64 @\"lifter_get_mapped_addr\""

        new_module_str = ""
        for line in module_str.splitlines():
            if not line.startswith(f_declaration):
                new_module_str = new_module_str + line + "\n"

        out_path = binaryninja.interaction.get_save_filename_input("Save LLVM IR File", ext="*.ll")

        if out_path is not None:
            if len(out_path) > 3:
                if out_path[-3:] != ".ll":
                    out_path += ".ll"

            with open(out_path, "w+") as f:
                f.write(new_module_str)

    def lift(self):
        functions = []

        self.create_stack()

        for fn in self.bv.functions:
            func = self.create_function_declaration(fn)
            functions.append((fn, func))

        addr_to_func = {}
        for fn in functions:
            fn_start = fn[0].address_ranges[0].start
            addr_to_func[fn_start] = fn[1]

            addr_map.add_addr_map_function_entry(fn_start, fn[1])

        for fn in functions:
            print("FUNCTION: " + str(fn[0].name))
            self.visit_function(fn[0], fn[1], addr_to_func)

        self.create_data_global()

        self.module = addr_map.create_addr_map(self.module)

        #print(self.module)
        self.dump()