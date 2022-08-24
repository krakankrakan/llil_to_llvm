from binaryninja import *
import llvmlite.ir as ll

bn_operation_to_builder_func_map = {
    binaryninja.LowLevelILOperation.LLIL_ADD : "add",
    binaryninja.LowLevelILOperation.LLIL_SUB : "sub",
    binaryninja.LowLevelILOperation.LLIL_OR :  "or_",
    binaryninja.LowLevelILOperation.LLIL_XOR : "xor",
    binaryninja.LowLevelILOperation.LLIL_AND : "and_",
    binaryninja.LowLevelILOperation.LLIL_LSL : "shl",
    binaryninja.LowLevelILOperation.LLIL_LSR : "lshr"
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
    
    def __init__(self, bv):
        self.bv = bv
        self.br = BinaryReader(bv, bv.endianness)
        self.module = ll.Module()
        self.builder = ll.IRBuilder()

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

    def visit_function(self, bn_func):

        #print(type(bn_func))
        print("Function: " + bn_func.name)

        func_type = bn_function_type_to_llvm(bn_func)

        print(func_type)

        func = ll.Function(self.module, func_type, bn_func.name)

        bb_entry = func.append_basic_block()
        self.builder.position_at_end(bb_entry)

        # Stack allocation for the registers (which are actually used)
        reg_to_alloca = self.generate_reg_allocas(bn_func)

        print("reg_to_alloca dict:")
        print(reg_to_alloca.keys())

        for i in bn_func.llil_instructions:
            print("Visit instruction:")
            print(i)

            self.visit_instruction(i, 0, reg_to_alloca)

            #for bb in func.blocks:
            #    for inst in bb.instructions:
            #        print("Operands:")
            #        for operand in inst.operands:
            #            print(operand)
            #        print("Instruction:")
            #        print(inst.opname)
            #        print(inst)

        # Dummy return instruction
        if (func_type.return_type == ll.VoidType()):
            self.builder.ret_void()
        else:
            self.builder.ret(ll.Constant(func_type.return_type, 0))

        #print(func)
        for bb in func.blocks:
            for inst in bb.instructions:
                print(inst)

        print("")

    #def reg_to_llvm(self, reg_name):
    #    if self.check_is_partial_reg_arm(reg_name):
    #        return self.get_full_reg_arm(reg_name)
    #    else:
    #        return reg_name

    def visit_instruction(self, llil_inst, level, reg_to_alloca, size=8):
        print((level + 1) * "   " + "visited:" + str(llil_inst.operation))
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
            a = self.visit_instruction(llil_inst.operands[0], level+1, reg_to_alloca, size)
            b = self.visit_instruction(llil_inst.operands[1], level+1, reg_to_alloca, size)

            # TODO: Is the correct size returned?
            return (
                a[0],
                call_method(
                    self.builder,
                    bn_operation_to_builder_func_map[llil_inst.operation],
                    a[1],
                    b[1]
            ))

        # Special handling for all other instructions
        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_LOAD:
            loaded = None

            loaded_value = self.visit_instruction(llil_inst.operands[0], level+1, reg_to_alloca, size)
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

                store_value = self.visit_instruction(llil_inst.operands[1], level+1, reg_to_alloca, self.get_reg_size_arm(reg_name))

                return (
                    0,
                    self.builder.store(
                        store_value[1],
                        self.builder.inttoptr(
                            self.visit_instruction(llil_inst.operands[0], level+1, reg_to_alloca)[1],
                            ll.PointerType(size_to_llvm_type(store_value[0]), 0)
                        )
                ))
            else:
                store_location = self.visit_instruction(llil_inst.operands[1], level+1, reg_to_alloca, size)

                store_value = self.visit_instruction(llil_inst.operands[0], level+1, reg_to_alloca, store_location[0])
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
                    self.visit_instruction(llil_inst.operands[0], level+1, reg_to_alloca, size)[1]
            ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_SX:
            return (
                size,
                self.builder.sext(
                    self.visit_instruction(llil_inst.operands[0], level+1, reg_to_alloca, size)[1],
                    size_to_llvm_type(size)
            ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_LOW_PART:
            return (
                int(size / 2),
                self.builder.trunc(
                    self.visit_instruction(llil_inst.operands[0], level+1, reg_to_alloca, size)[1],
                    size_to_llvm_type(int(size / 2))
            ))

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_SET_REG:
            reg_name = llil_inst.operands[0].name

            #print("visit a:")
            a = self.visit_instruction(llil_inst.operands[1], level+1, reg_to_alloca, self.get_reg_size_arm(reg_name))[1]
            #print("a:")
            #print(a)

            self.handle_reg_assign_arm(
                reg_name,
                a,
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
            #return llil_inst.operands[0]

            #self.builder.

    def dump(self):
        with open("/Users/krakan/out.txt", "w+") as f:
            f.write(self.module.__str__())

    def lift(self):
        self.create_data_global()

        for fn in self.bv.functions:
            self.visit_function(fn)

        print(self.module)
        #self.dump()