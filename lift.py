from binaryninja import *
import llvmlite.ir as ll

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

    def generate_reg_allocas_recursive(self, llil_inst, reg_to_alloca):

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_REG:
            reg_name = llil_inst.operands[0].name

            alloca = self.builder.alloca(
                size_to_llvm_type(
                    self.bv.arch.regs[reg_name].size
                )
            ) 
            reg_to_alloca[reg_name] = alloca

            return reg_to_alloca

        for operand in llil_inst.operands:
            if issubclass(type(operand), binaryninja.lowlevelil.LowLevelILInstruction):
                reg_to_alloca = self.generate_reg_allocas_recursive(operand, reg_to_alloca)

        return reg_to_alloca

    def generate_reg_allocas(self, bn_func):
        reg_to_alloca = {}

        for llil_inst in bn_func.llil_instructions:
            reg_to_alloca = self.generate_reg_allocas_recursive(llil_inst, reg_to_alloca)

        return reg_to_alloca

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

        # Dummy return instruction
        if (func_type.return_type == ll.VoidType()):
            self.builder.ret_void()
        else:
            self.builder.ret(ll.Constant(func_type.return_type, 0))

        for i in bn_func.llil_instructions:
            self.visit_instruction(i, 0, reg_to_alloca)

    def visit_instruction(self, llil_inst, level, reg_to_alloca):
        print(level * "   " + "visited:" + str(llil_inst.operation))
        print(level * "   " + "operands: " + str(llil_inst.operands))

        for operand in llil_inst.operands:
            if issubclass(type(operand), binaryninja.lowlevelil.LowLevelILInstruction):
                self.visit_instruction(operand, level+1, reg_to_alloca)
            else:
                print((level + 1) * "   " + "non-visited:" + str(type(operand)))

        #if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_ADD:
        #    self.builder.add(
        #        self.visit_instruction(llil_inst.operands[0]),
        #        self.visit_instruction(llil_inst.operands[1])
        #    )

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_REG:
            reg_name = llil_inst.operands[0].name
            return reg_to_alloca[reg_name]

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_CONST:
            return ll.Constant(size_to_llvm_type(8), llil_inst.operands[0])
            #return llil_inst.operands[0]

    def dump(self):
        with open("/Users/krakan/out.txt", "w+") as f:
            f.write(self.module.__str__())

    def lift(self):
        self.create_data_global()

        for fn in self.bv.functions:
            self.visit_function(fn)

        #print(self.module)
        self.dump()