import llvmlite.ir as ll

def cast_to_type(builder, value, dst_type):
    src_type = value.type

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

    elif isinstance(src_type, ll.FloatType) and isinstance(dst_type, ll.IntType):
        return builder.bitcast(
            value,
            dst_type
        )

    elif isinstance(src_type, ll.IntType) and isinstance(dst_type, ll.FloatType):
        return builder.bitcast(
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