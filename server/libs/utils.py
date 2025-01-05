def decode_all_bytes(dict_: dict, is_decode_keys: bool = True, is_decode_values: bool = True, encoding: str = "utf-8"):
    # type: (dict, bool, bool, str) -> dict
    new_dict = dict()
    for k, v in dict_.items():
        k = k.decode() if isinstance(k, bytes) and is_decode_keys else k
        v = v.decode() if isinstance(v, bytes) and is_decode_values else v
        if isinstance(v, dict):
            v = decode_all_bytes(v, is_decode_keys, is_decode_values, encoding)
        new_dict[k] = v
    return new_dict


def bytes2hex(b, is_for_display: bool = True, is_for_web_display: bool = True, is_break_at_first: bool = True):
    # type: (bytes|str, bool, bool, bool) -> str
    if isinstance(b, str):
        b = bytes(b, "utf-8")
    if is_for_display:
        hex_str = "" if not is_break_at_first else ("<br>" if is_for_web_display else "\n")
        for i, byte in enumerate(b):
            hex_str += f"{byte:02x}"
            if i % 16 == 15:
                hex_str += "<br>" if is_for_web_display else "\n"
            elif i % 8 == 7:
                hex_str += "&ensp;&ensp;" if is_for_web_display else "  "
            else:
                hex_str += "&ensp;" if is_for_web_display else " "
        return hex_str.strip()
    else:
        return b.hex()


def set_default(dict_:dict, key, value):
    '''
    与python内置的setdefault的区别是：要检查key对应的value是否为None
    '''
    # !!! 注意：与python内置的setdefault的区别是：要检查key对应的value是否为None
    if key not in dict_ or dict_[key] is None:
        dict_[key] = value
    return dict_


def set_default_dd(dict_:dict, key, value:dict):
    '''
    为字典嵌套字典设置初始值
    '''
    set_default(dict_, key, value)
    for k, v in value.items():
        set_default(dict_[key], k, v)
    return dict_


def set_default_session(session, key, value):
    '''
    为request.session设置初始值
    '''
    if isinstance(value, dict):
        set_default_dd(session, key, value)
        # 注意一定要设置modified为True
        session.modified = True
    else:
        set_default(session, key, value)
    return session


def update_session(session, key, value:dict):
    '''
    为字典嵌套字典的session的一个key更新value
    '''
    session[key].update(value)
    # 注意一定要设置modified为True
    session.modified = True
    
