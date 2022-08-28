; ModuleID = 'map_addr.c'
source_filename = "map_addr.c"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"
target triple = "arm64-apple-macosx12.0.0"

@lifter_addr_map_size = external global i32, align 4
@lifter_addr_map = external global [0 x i64], align 8
@.str = private unnamed_addr constant [30 x i8] c"Could not map address: 0x%lx\0A\00", align 1

; Function Attrs: noinline nounwind optnone ssp uwtable
define i64 @lifter_get_mapped_addr(i64 noundef %addr) #0 {
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
  br label %for.cond, !llvm.loop !9

for.end:                                          ; preds = %for.cond
  %17 = load i64, i64* %addr.addr, align 8
  %call = call i32 (i8*, ...) @printf(i8* noundef getelementptr inbounds ([30 x i8], [30 x i8]* @.str, i64 0, i64 0), i64 noundef %17)
  store i64 0, i64* %retval, align 8
  br label %return

return:                                           ; preds = %for.end, %if.then
  %18 = load i64, i64* %retval, align 8
  ret i64 %18
}

declare i32 @printf(i8* noundef, ...) #1

attributes #0 = { noinline nounwind optnone ssp uwtable "frame-pointer"="non-leaf" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+crc,+crypto,+dotprod,+fp-armv8,+fp16fml,+fullfp16,+lse,+neon,+ras,+rcpc,+rdm,+sha2,+sha3,+sm4,+v8.5a,+zcm,+zcz" }
attributes #1 = { "frame-pointer"="non-leaf" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+crc,+crypto,+dotprod,+fp-armv8,+fp16fml,+fullfp16,+lse,+neon,+ras,+rcpc,+rdm,+sha2,+sha3,+sm4,+v8.5a,+zcm,+zcz" }

!llvm.module.flags = !{!0, !1, !2, !3, !4, !5, !6, !7}
!llvm.ident = !{!8}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 1, !"branch-target-enforcement", i32 0}
!2 = !{i32 1, !"sign-return-address", i32 0}
!3 = !{i32 1, !"sign-return-address-all", i32 0}
!4 = !{i32 1, !"sign-return-address-with-bkey", i32 0}
!5 = !{i32 7, !"PIC Level", i32 2}
!6 = !{i32 7, !"uwtable", i32 2}
!7 = !{i32 7, !"frame-pointer", i32 1}
!8 = !{!"clang version 15.0.0 (https://github.com/llvm/llvm-project.git dbc32e2aa72ed1a46c85160755820c471689dcc1)"}
!9 = distinct !{!9, !10}
!10 = !{!"llvm.loop.mustprogress"}
