import llvmlite.ir as ll
import llil_to_llvm.util as util

def size_to_llvm_type(size):
    if size != 0:
        return ll.IntType(size * 8)

class ArchitectureFunctionsBase:
    def check_is_partial_reg(self, reg_name):
        pass

    def get_full_reg(self, reg_name):
        pass

    def get_reg_size(self, reg_name):
        pass

     # Casts a register pointer to the needed value.
    def handle_reg_ptr(self, reg_name, reg_to_alloca):
        if self.check_is_partial_reg(reg_name):
            full_reg = self.get_full_reg(reg_name)

            #casted_reg = self.builder.bitcast(
            #    reg_to_alloca[full_reg],
            #    ll.PointerType(size_to_llvm_type(self.get_reg_size(reg_name)), 0)
            #)

            casted_reg = util.cast_to_type(
                self.builder,
                reg_to_alloca[full_reg],
                ll.PointerType(size_to_llvm_type(self.get_reg_size(reg_name)), 0)
            )

            return casted_reg
        else:
            return reg_to_alloca[reg_name]

    # Casts an LLVM Value to the size needed by a register to hold the value.
    def handle_reg_assign(self, reg_name, value, reg_to_alloca):
        reg_ptr = self.handle_reg_ptr(reg_name, reg_to_alloca)

        self.builder.store(
            value,
            reg_ptr
        )

    def handle_reg_load(self, reg_name, reg_to_alloca):
        if self.check_is_partial_reg(reg_name):
            full_reg = self.get_full_reg(reg_name)

            loaded_reg = self.builder.load(
                reg_to_alloca[full_reg]
            )

            #return self.builder.bitcast(
            #    loaded_reg,
            #    size_to_llvm_type(self.get_reg_size(reg_name))
            #)

            return util.cast_to_type(
                self.builder,
                loaded_reg,
                size_to_llvm_type(self.get_reg_size(reg_name))
            )
        else:
            loaded_reg = self.builder.load(
                reg_to_alloca[reg_name]
            )

            return loaded_reg

    def get_return_register(self):
        pass

    def get_arg_registers(self, count, reg_to_alloca):
        pass

class ARMFunctions(ArchitectureFunctionsBase):

    def __init__(self, builder):
        self.builder = builder

    def check_is_partial_reg(self, reg_name):
        if reg_name[0] == "w":
            return True
        return False

    def get_full_reg(self, reg_name):
        return "x" + reg_name[1:]

    def get_reg_size(self, reg_name):
        if reg_name[0] == "x":
            return 8
        if reg_name[0] == "w":
            return 4
        else:
            return 8

    def get_return_register(self):
        return "x0"

    def get_arg_registers(self, count, reg_to_alloca):
        param_regs = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]

        if count == 0:
            return []
        elif count <= 8:
            loaded_regs = []

            for param_reg in param_regs[0:count]:
                loaded_regs.append(self.handle_reg_load(param_reg, reg_to_alloca))

            return loaded_regs
        else:
            raise Exception("Too many function arguments!")

class x86Functions(ArchitectureFunctionsBase):
    def __init__(self, builder):
        self.builder = builder

    def check_is_partial_reg(self, reg_name):
        # Registers like al, cl, dl, bl
        if len(reg_name) == 2:
            return True

        # eax, ebx, ..., r8w, r9w, ...
        if len(reg_name) == 3:
            if reg_name[0] == "e" or reg_name[2] == "w":
                return True

        if len(reg_name) == 4:
            if reg_name[3] == "w":
                return True

        return False

    def get_full_reg(self, reg_name):
        if len(reg_name) == 2:
            return "r" + reg_name[0] + "x"

        if len(reg_name) == 3:
            if reg_name[0] == "e":
                return "r" + reg_name[1:]

            if reg_name[2] == "w":
                return reg_name[0:2]

        if len(reg_name) == 4:
            if reg_name[3] == "w":
                return reg_name[0:3]

    def get_return_register(self):
        return "rax"
    
    def get_arg_registers(self, count, reg_to_alloca):
        param_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

        if count == 0:
            return []
        elif count <= 6:
            loaded_regs = []

            for param_reg in param_regs[0:count]:
                loaded_regs.append(self.handle_reg_load(param_reg, reg_to_alloca))

            return loaded_regs
        else:
            raise Exception("Too many function arguments!")

class RISCVFunctions(ArchitectureFunctionsBase):
    def __init__(self, builder):
        self.builder = builder

    def check_is_partial_reg(self, reg_name):
        return False

    def get_full_reg(self, reg_name):
        return reg_name

    def get_reg_size(self, reg_name):
        return 8

    def get_return_register(self):
        return "a0"

    def get_arg_registers(self, count, reg_to_alloca):
        param_regs = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]

        if count == 0:
            return []
        elif count <= 8:
            loaded_regs = []

            for param_reg in param_regs[0:count]:
                loaded_regs.append(self.handle_reg_load(param_reg, reg_to_alloca))

            return loaded_regs
        else:
            raise Exception("Too many function arguments!")