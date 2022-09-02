; ModuleID = 'main.c'
source_filename = "main.c"

define i32 @main() {
  %1 = alloca i32, align 4
  store i32 0, i32* %1, align 4
  call void bitcast (void (...)* @__lifter_init to void ()*)()
  %2 = call i64 bitcast (i64 (...)* @_main to i64 ()*)()
  ret i32 0
}

declare void @__lifter_init(...)

declare i64 @_main(...)