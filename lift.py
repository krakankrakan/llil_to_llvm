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

    def visit_function(self, bn_func):

        #print(type(bn_func))
        print("Function: " + bn_func.name)

        func_type = bn_function_type_to_llvm(bn_func)

        print(func_type)

        func = ll.Function(self.module, func_type, bn_func.name)

        bb_entry = func.append_basic_block()
        self.builder.position_at_end(bb_entry)

        if (func_type.return_type == ll.VoidType()):
            self.builder.ret_void()
        else:
            self.builder.ret(ll.Constant(func_type.return_type, 0))

        for i in bn_func.llil_instructions:
            self.visit_instruction(i)

    def visit_instruction(self, llil_inst):
        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_ADD:
            self.builder.add(
                self.visit_instruction(llil_inst.operands[0]),
                self.visit_instruction(llil_inst.operands[1])
            )

        if llil_inst.operation == binaryninja.LowLevelILOperation.LLIL_CONST:
            self.builder.const(
                ll.Constant(llil_inst.operands[0], llil_inst.operands[1])
            )

    def dump(self):
        with open("/Users/krakan/out.txt", "w+") as f:
            f.write(self.module.__str__())

    def lift(self):
        self.create_data_global()

        for fn in self.bv.functions:
            self.visit_function(fn)

        print(self.module)

        #self.dump()