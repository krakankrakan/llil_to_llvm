from binaryninja import *
import llvmlite.ir as ll

# Maps addresses of the original binary to new LLVM Values
addr_map = []

# C code (data/map_addr.c) emitted as LLVM IR via: 
#   clang -Wall map_addr.c -o map_addr.ll -S -emit-llvm
ir_map_code = r"""
@.str = private unnamed_addr constant [30 x i8] c"Could not map address: 0x%lx\0A\00", align 1

; Function Attrs: noinline nounwind optnone ssp uwtable
define i64 @lifter_get_mapped_addr(i64 noundef %addr) {
entry:
  %retval = alloca i64, align 8
  %addr.addr = alloca i64, align 8
  %i = alloca i32, align 4
  %region_addr = alloca i64, align 8
  %region_size = alloca i64, align 8
  %target_addr = alloca i64, align 8
  store i64 %addr, i64* %addr.addr, align 8
  store i32 0, i32* %i, align 4
  br label %for.cond

for.cond:                                         ; preds = %for.inc, %entry
  %0 = load i32, i32* %i, align 4
  %1 = load i32, i32* @lifter_addr_map_size, align 4
  %mul = mul i32 %1, 3
  %cmp = icmp ult i32 %0, %mul
  br i1 %cmp, label %for.body, label %for.end

for.body:                                         ; preds = %for.cond
  %2 = load i32, i32* %i, align 4
  %idxprom = zext i32 %2 to i64
  %arrayidx = getelementptr inbounds [0 x i64], [0 x i64]* @lifter_addr_map, i64 0, i64 %idxprom
  %3 = load i64, i64* %arrayidx, align 8
  store i64 %3, i64* %region_addr, align 8
  %4 = load i32, i32* %i, align 4
  %add = add i32 %4, 1
  %idxprom1 = zext i32 %add to i64
  %arrayidx2 = getelementptr inbounds [0 x i64], [0 x i64]* @lifter_addr_map, i64 0, i64 %idxprom1
  %5 = load i64, i64* %arrayidx2, align 8
  store i64 %5, i64* %region_size, align 8
  %6 = load i32, i32* %i, align 4
  %add3 = add i32 %6, 2
  %idxprom4 = zext i32 %add3 to i64
  %arrayidx5 = getelementptr inbounds [0 x i64], [0 x i64]* @lifter_addr_map, i64 0, i64 %idxprom4
  %7 = load i64, i64* %arrayidx5, align 8
  store i64 %7, i64* %target_addr, align 8
  %8 = load i64, i64* %addr.addr, align 8
  %9 = load i64, i64* %region_addr, align 8
  %cmp6 = icmp uge i64 %8, %9
  br i1 %cmp6, label %land.lhs.true, label %if.end

land.lhs.true:                                    ; preds = %for.body
  %10 = load i64, i64* %addr.addr, align 8
  %11 = load i64, i64* %region_addr, align 8
  %12 = load i64, i64* %region_size, align 8
  %add7 = add i64 %11, %12
  %cmp8 = icmp ule i64 %10, %add7
  br i1 %cmp8, label %if.then, label %if.end

if.then:                                          ; preds = %land.lhs.true
  %13 = load i64, i64* %addr.addr, align 8
  %14 = load i64, i64* %region_addr, align 8
  %sub = sub i64 %13, %14
  %15 = load i64, i64* %target_addr, align 8
  %add9 = add i64 %sub, %15
  store i64 %add9, i64* %retval, align 8
  br label %return

if.end:                                           ; preds = %land.lhs.true, %for.body
  br label %for.inc

for.inc:                                          ; preds = %if.end
  %16 = load i32, i32* %i, align 4
  %add10 = add i32 %16, 3
  store i32 %add10, i32* %i, align 4
  br label %for.cond

for.end:                                          ; preds = %for.cond
  %17 = load i64, i64* %addr.addr, align 8
  %call = call i32 (i8*, ...) @printf(i8* noundef getelementptr inbounds ([30 x i8], [30 x i8]* @.str, i64 0, i64 0), i64 noundef %17)
  store i64 0, i64* %retval, align 8
  br label %return

return:                                           ; preds = %for.end, %if.then
  %18 = load i64, i64* %retval, align 8
  ret i64 %18
}

declare i32 @printf(i8* noundef, ...)
"""

# This function maps addresses of the "old" binary to new addresses.
# For example, function addresses in the original binary are mapped
# to their lifted counterparts.
#
# Here, the mapper function is appended to the passed module.
def insert_lifter_get_mapped_addr_func(module):
    lifter_get_mapped_addr = ll.Function(
        module,
        ll.FunctionType(
            ll.IntType(64),
            [ ll.IntType(64) ]
        ),
        name="lifter_get_mapped_addr"
    )

    return lifter_get_mapped_addr

def create_addr_map(module):
    global addr_map

    flattened_addr_map = []#list(sum(addr_map, ()))

    for addr in addr_map:
        flattened_addr_map.append(addr[0])
        flattened_addr_map.append(addr[1])
        flattened_addr_map.append(0)
    
    # Global variable for "lifter_addr_map"
    lifter_addr_map_initializer = ll.Constant(
        ll.ArrayType(ll.IntType(64), len(flattened_addr_map)),
        flattened_addr_map
    )

    lifter_addr_map = ll.GlobalVariable(module, lifter_addr_map_initializer.type, name="lifter_addr_map")
    lifter_addr_map.linkage = 'internal'
    lifter_addr_map.global_constant = True
    lifter_addr_map.initializer = lifter_addr_map_initializer

    # Global variable for "lifter_addr_map_size"
    lifter_addr_map_size_initializer = ll.Constant(
        ll.IntType(32),
        len(addr_map)
    )

    lifter_addr_map_size = ll.GlobalVariable(module, lifter_addr_map_size_initializer.type, name="lifter_addr_map_size")
    lifter_addr_map_size.linkage = 'internal'
    lifter_addr_map_size.global_constant = True
    lifter_addr_map_size.initializer = lifter_addr_map_size_initializer

    # Generate the lifter initialization function
    init_func = ll.Function(module, ll.FunctionType(ll.VoidType(), []), "__lifter_init")
    builder = ll.IRBuilder()
    bb_entry = init_func.append_basic_block()
    builder.position_at_end(bb_entry)

    for i in range(0, len(addr_map)):
        ptr = builder.gep(lifter_addr_map, [ ll.Constant(ll.IntType(64), 0), ll.Constant(ll.IntType(64), 2 + i*3) ])
        value = builder.ptrtoint(
            addr_map[i][2],
            ll.IntType(64)
        )
        #value = builder.inttoptr(
        #        value
        #        ll.IntType(64)
        #    )
        builder.store(
            value,
            ptr
        )

    builder.ret_void()

    return module

def add_addr_map_function_entry(original_addr, llvm_func):
    global addr_map

    addr_map.append((original_addr, 0, llvm_func))

def add_addr_map_data_section(original_addr, size, data_global):
    global addr_map

    addr_map.append((original_addr, size, data_global))