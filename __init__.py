from binaryninja import *
import llil_to_llvm.lift as lift

class LLIRLifter(BackgroundTaskThread):
    def __init__(self, msg, bv):
        BackgroundTaskThread.__init__(self, msg, True)
        self.bv = bv

    def run(self):
        # First, remove all possible duplicate function names. Simply append "_".
        seed_func_names = []
        for function in self.bv.functions:
            if function.name in seed_func_names:
                while function.name in seed_func_names:
                    function.name = function.name + "_"

            seed_func_names.append(function.name)

        l = lift.Lifter(self.bv)
        l.lift()
        pass

def lift_functions(bv):
    task = LLIRLifter("Lifting LLIR to LLVM IR", bv)
    task.run()

PluginCommand.register("LLIR to LLVM IR", "Lifts Binary Ninja's LLIR to LLVM IR.", lift_functions)