import llvmlite.ir as ll

def cast_to_type(builder, value, dst_type):
    src_type = value.type

    print("src_type: " + str(src_type))
    print("dst_type: " + str(dst_type))

    if src_type == dst_type:
        return value

    if isinstance(src_type, ll.PointerType) and isinstance(dst_type, ll.IntType):
        return builder.ptrtoint(
            value,
            dst_type
        )

    elif isinstance(src_type, ll.IntType) and isinstance(dst_type, ll.PointerType):
        return builder.inttoptr(
            value,
            dst_type
        )

    elif isinstance(src_type, ll.IntType) and isinstance(dst_type, ll.IntType):
        if src_type.width == dst_type.width:
            return value

        elif src_type.width < dst_type.width:
            return builder.zext(
                value,
                dst_type
            )

        elif src_type.width > dst_type.width:
            return builder.trunc(
                value,
                dst_type
            )

    elif (isinstance(src_type, ll.FloatType) or isinstance(src_type, ll.DoubleType)) and isinstance(dst_type, ll.IntType):
        if isinstance(src_type, ll.FloatType):
            target_size = 32
        else :
            target_size = 64

        if target_size != dst_type.width:
            value = cast_to_type(builder, value, ll.IntType(target_size))

        return builder.bitcast(
            value,
            dst_type
        )

    elif isinstance(src_type, ll.IntType) and (isinstance(dst_type, ll.FloatType) or isinstance(dst_type, ll.DoubleType)):
        if isinstance(dst_type, ll.FloatType):
            target_size = 32
        else :
            target_size = 64

        if target_size != src_type.width:
            value = cast_to_type(builder, value, ll.IntType(target_size))

        return builder.bitcast(
            value,
            dst_type
        )

    elif isinstance(src_type, ll.FloatType) and isinstance(dst_type, ll.DoubleType):
        return builder.fpext(
            value,
            dst_type
        )

    elif isinstance(src_type, ll.DoubleType) and isinstance(dst_type, ll.FloatType):
        return builder.fptrunc(
            value,
            dst_type
        )

    else:
        return builder.bitcast(
            value,
            dst_type
        )
    
    return None

def get_null(dst_type):
    if isinstance(dst_type, ll.IntType):
        return ll.Constant(ll.IntType(64), 0)

    elif isinstance(dst_type, ll.PointerType):
        return ll.Constant(dst_type, None)