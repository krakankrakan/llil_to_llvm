from binaryninja import *
import llil_to_llvm.lift as lift

class LLIRLifter(BackgroundTaskThread):
    def __init__(self, msg, bv):
        BackgroundTaskThread.__init__(self, msg, True)
        self.bv = bv

    def run(self):
        l = lift.Lifter(self.bv)
        l.lift()
        pass

def lift_functions(bv):
    task = LLIRLifter("Lifting LLIR to LLVM IR", bv)
    task.run()

PluginCommand.register("LLIR to LLVM IR", "Lifts Binary Ninja's LLIR to LLVM IR.", lift_functions)