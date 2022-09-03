; ModuleID = 'map_addr.c'
source_filename = "map_addr.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@lifter_addr_map_size = external dso_local global i32, align 4
@lifter_addr_map = external dso_local global [0 x i64], align 8
@.str = private unnamed_addr constant [30 x i8] c"Could not map address: 0x%lx\0A\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i64 @lifter_get_mapped_addr(i64 %0) #0 {
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
  br label %8, !llvm.loop !2

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

declare dso_local i32 @printf(i8*, ...) #1

attributes #0 = { noinline nounwind optnone uwtable "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"Ubuntu clang version 12.0.0-3ubuntu1~21.04.2"}
!2 = distinct !{!2, !3}
!3 = !{!"llvm.loop.mustprogress"}
