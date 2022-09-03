from binaryninja import *
import llvmlite.ir as ll

# Maps addresses of the original binary to new LLVM Values
addr_map = []

# C code (data/map_addr.c) emitted as LLVM IR via: 
#   clang -Wall map_addr.c -o map_addr.ll -S -emit-llvm
ir_map_code = r"""
@.str = private unnamed_addr constant [30 x i8] c"Could not map address: 0x%lx\0A\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i64 @lifter_get_mapped_addr(i64 %0) {
  %2 = alloca i64, align 8
  %3 = alloca i64, align 8
  %4 = alloca i32, align 4
  %5 = alloca i64, align 8
  %6 = alloca i64, align 8
  %7 = alloca i64, align 8
  store i64 %0, i64* %3, align 8
  store i32 0, i32* %4, align 4
  br label %8

8:                                                ; preds = %44, %1
  %9 = load i32, i32* %4, align 4
  %10 = load i32, i32* @lifter_addr_map_size, align 4
  %11 = mul i32 %10, 3
  %12 = icmp ult i32 %9, %11
  br i1 %12, label %13, label %47

13:                                               ; preds = %8
  %14 = load i32, i32* %4, align 4
  %15 = zext i32 %14 to i64
  %16 = getelementptr inbounds [0 x i64], [0 x i64]* @lifter_addr_map, i64 0, i64 %15
  %17 = load i64, i64* %16, align 8
  store i64 %17, i64* %5, align 8
  %18 = load i32, i32* %4, align 4
  %19 = add i32 %18, 1
  %20 = zext i32 %19 to i64
  %21 = getelementptr inbounds [0 x i64], [0 x i64]* @lifter_addr_map, i64 0, i64 %20
  %22 = load i64, i64* %21, align 8
  store i64 %22, i64* %6, align 8
  %23 = load i32, i32* %4, align 4
  %24 = add i32 %23, 2
  %25 = zext i32 %24 to i64
  %26 = getelementptr inbounds [0 x i64], [0 x i64]* @lifter_addr_map, i64 0, i64 %25
  %27 = load i64, i64* %26, align 8
  store i64 %27, i64* %7, align 8
  %28 = load i64, i64* %3, align 8
  %29 = load i64, i64* %5, align 8
  %30 = icmp uge i64 %28, %29
  br i1 %30, label %31, label %43

31:                                               ; preds = %13
  %32 = load i64, i64* %3, align 8
  %33 = load i64, i64* %5, align 8
  %34 = load i64, i64* %6, align 8
  %35 = add i64 %33, %34
  %36 = icmp ule i64 %32, %35
  br i1 %36, label %37, label %43

37:                                               ; preds = %31
  %38 = load i64, i64* %3, align 8
  %39 = load i64, i64* %5, align 8
  %40 = sub i64 %38, %39
  %41 = load i64, i64* %7, align 8
  %42 = add i64 %40, %41
  store i64 %42, i64* %2, align 8
  br label %51

43:                                               ; preds = %31, %13
  br label %44

44:                                               ; preds = %43
  %45 = load i32, i32* %4, align 4
  %46 = add i32 %45, 3
  store i32 %46, i32* %4, align 4
  br label %8

47:                                               ; preds = %8
  %48 = load i64, i64* %3, align 8
  %49 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([30 x i8], [30 x i8]* @.str, i64 0, i64 0), i64 %48)
  %50 = load i64, i64* %3, align 8
  store i64 %50, i64* %2, align 8
  br label %51

51:                                               ; preds = %47, %37
  %52 = load i64, i64* %2, align 8
  ret i64 %52
}

declare dso_local i32 @printf(i8*, ...)
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

    print(addr_map)
    print(flattened_addr_map)

    lifter_addr_map = ll.GlobalVariable(module, lifter_addr_map_initializer.type, name="lifter_addr_map")
    lifter_addr_map.linkage = 'internal'
    lifter_addr_map.global_constant = False
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
        value = builder.ptrtoint(
            addr_map[i][2],
            ll.IntType(64)
        )
        ptr = builder.gep(lifter_addr_map, [ ll.Constant(ll.IntType(64), 0), ll.Constant(ll.IntType(64), 2 + i*3) ])

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