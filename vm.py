
import sys
import functools
import types
# import dis
import opcode

assert sys.version_info.major == 3

class Context:
    def __init__(self, code, args):
        self.code = code
        self.pc = 0
        self.stack = []
        self.blocks = []
        self.local_vars = {}

        for i, v in enumerate(args):
            self.local_vars[self.code.co_varnames[i]] = v

class VM:
    '''for python 3.10'''

    def __init__(self):
        self.module_object = None
        self.code = None

        self.global_vars = {}
        self.native_vars = set()

    def import_function(self, function_object, global_vars = {}):
        self.code = function_object.__code__

        if global_vars:
            self.global_vars = global_vars

    def import_module(self, module_object):
        for k, v in module_object.__dict__.items():
            if not k.startswith('__'):
                self.global_vars[k] = v


        self.module_object = module_object

    def import_src(self, src):
        self.contexts = []
        # print(dir(src))
        print(src.co_code)

        self.code = src
        self.run([])

    def invoke(self, func, args):
        print(func, args)
        # dis.dis(func.__code__.co_code)
        if type(func) == type or func in self.native_vars:
            result = functools.partial(func, *args)()
            return result

        print(func.__code__.co_argcount, args)
        # assert func.__code__.co_argcount == len(args)
        assert func.__code__.co_code
        ctx = Context(func.__code__, args)

        pc = -1
        while pc != ctx.pc:
            pc = ctx.pc
            # try:
            r = self.step(ctx)
            if r is not None:
                print('return value', r)
                return r

    def run(self, args, function_name = None):
        if self.module_object and function_name:
            function_object = self.module_object.__dict__[function_name]
            assert type(function_object) == types.FunctionType
            self.import_function(function_object)
        elif function_name in self.global_vars:
            function_object = self.global_vars[function_name]
            assert type(function_object) == types.FunctionType
            self.import_function(function_object)

        self.global_vars['type'] = type
        self.global_vars['int'] = int
        self.global_vars['str'] = str
        self.global_vars['bytes'] = bytes
        self.global_vars['set'] = set
        self.global_vars['dict'] = dict
        self.global_vars['list'] = list
        self.global_vars['range'] = range
        self.global_vars['len'] = len
        # self.global_vars['open'] = open
        self.global_vars['AssertionError'] = AssertionError
        self.native_vars.add(type)
        self.native_vars.add(int)
        self.native_vars.add(str)
        self.native_vars.add(bytes)
        self.native_vars.add(dict)
        self.native_vars.add(list)
        self.native_vars.add(range)
        self.native_vars.add(len)

        assert self.code.co_argcount == len(args)
        assert self.code.co_code
        ctx = Context(self.code, args)

        # print('\n')
        # print('global_vars', self.global_vars)
        # print('\n')
        # print('co_code', [hex(i) for i in self.co_code])
        # print('co_varnames', self.co_varnames)
        # print('co_names', self.co_names) # for method
        # print('co_consts', self.co_consts)
        # print('co_argcount', self.co_argcount)
        # print('---')

        pc = -1
        while pc != ctx.pc:
            pc = ctx.pc
            # try:
            r = self.step(ctx)
            if r is not None:
                print('return value', r)
                return r
            # except BaseException as e:
            #     print('except', e.__class__.__name__, dir(e.__class__))
            #     print('blocks', ctx.blocks)
            #     if ctx.blocks:
            #         new_pc = ctx.blocks[-1]
            #         ctx.pc = new_pc
            # print('stack', ctx.stack)
        # print('---')
        # print('global_vars', self.global_vars)
        return False

    def step(self, ctx):
        co_code = ctx.code.co_code
        # print('PC', ctx.pc, hex(co_code[ctx.pc]), opcode.opname[co_code[ctx.pc]])
        # print('local_vars', self.local_vars)
        if co_code[ctx.pc] == 0x0: # NOP
            print('NOP')

        elif co_code[ctx.pc] == 0x1: # POP_TOP
            # print('POP_TOP')
            ctx.stack.pop()
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x2: # ROT_TWO
            # print('ROT_TWO')
            first = ctx.stack.pop()
            second = ctx.stack.pop()
            ctx.stack.append(first)
            ctx.stack.append(second)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x3: # ROT_THREE
            # print('ROT_THREE')
            first = ctx.stack.pop()
            second = ctx.stack.pop()
            third = ctx.stack.pop()
            ctx.stack.append(first)
            ctx.stack.append(third)
            ctx.stack.append(second)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x4: # DUP_TOP
            # print('DUP_TOP')
            first = ctx.stack[-1]
            ctx.stack.append(first)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x5: # DUP_TOP_TWO
            # print('DUP_TOP_TWO')
            second = ctx.stack[-2]
            first = ctx.stack[-1]
            ctx.stack.append(second)
            ctx.stack.append(first)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x13: # BINARY_POWER
            exp = ctx.stack.pop()
            base = ctx.stack.pop()
            # print('BINARY_POWER', base, exp)
            ctx.stack.append(base ** exp)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x14: # BINARY_MULTIPLY
            right = ctx.stack.pop()
            left = ctx.stack.pop()
            # print('BINARY_MULTIPLY', left, right)
            ctx.stack.append(left*right)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x16: # BINARY_MODULO
            right = ctx.stack.pop()
            left = ctx.stack.pop()
            # print('BINARY_MODULO', left, right)
            ctx.stack.append(left%right)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x17: # BINARY_ADD
            right = ctx.stack.pop()
            left = ctx.stack.pop()
            # print('BINARY_ADD', left, right)
            ctx.stack.append(left+right)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x18: # BINARY_SUBTRACT
            right = ctx.stack.pop()
            left = ctx.stack.pop()
            # print('BINARY_SUBTRACT', left, right)
            ctx.stack.append(left-right)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x19: # BINARY_SUBSCR
            idx = ctx.stack.pop()
            obj = ctx.stack.pop()
            ctx.stack.append(obj[idx])
            # print('BINARY_SUBSCR')
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x1a: # BINARY_FLOOR_DIVIDE
            right = ctx.stack.pop()
            left = ctx.stack.pop()
            # print('BINARY_FLOOR_DIVIDE', left, right)
            ctx.stack.append(left//right)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x1b: # BINARY_TRUE_DIVIDE
            right = ctx.stack.pop()
            left = ctx.stack.pop()
            # print('BINARY_TRUE_DIVIDE', left, right)
            ctx.stack.append(left/right)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x37: # INPLACE_ADD
            val = ctx.stack.pop()
            obj = ctx.stack.pop()
            # print('INPLACE_ADD', obj, '+=', val)

            ctx.stack.append(obj + val)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x38: # INPLACE_SUBTRACT
            val = ctx.stack.pop()
            obj = ctx.stack.pop()
            # print('INPLACE_SUBTRACT', obj, '-=', val)

            ctx.stack.append(obj - val)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x3c: # STORE_SUBSCR
            key = ctx.stack.pop()
            obj = ctx.stack.pop()
            val = ctx.stack.pop()
            # print('STORE_SUBSCR', obj, '[', key, '] =', val)

            obj[key] = val
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x44: # GET_ITER
            val = ctx.stack.pop()
            ctx.stack.append(iter(val))
            ctx.pc += 2

        ## MUST DISABLE
        elif co_code[ctx.pc] == 0x47: # LOAD_BUILD_CLASS
            raise

        elif co_code[ctx.pc] == 0x51: # WITH_CLEANUP_START
            # val = ctx.stack.pop()
            # print('WITH_CLEANUP_START')
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x52: # WITH_CLEANUP_FINISH
            # val = ctx.stack.pop()
            # print('WITH_CLEANUP_FINISH')
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x53: # RETURN_VALUE
            val = ctx.stack.pop()
            # print('RETURN_VALUE', val)
            return val

        elif co_code[ctx.pc] == 0x57: # POP_BLOCK
            # param = co_code[ctx.pc+1]
            delta = ctx.blocks.pop()
            print('POP_BLOCK', delta)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x58: # END_FINALLY
            # print('END_FINALLY')
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x59: # POP_EXCEPT
            print('POP_EXCEPT')
            print('blocks', ctx.blocks)
            ctx.blocks.pop()
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x5a: # STORE_NAME
            val = ctx.stack.pop()
            param = co_code[ctx.pc+1]
            print('STORE_NAME', param)
            print('STORE_NAME', ctx.code.co_names)
            varname = ctx.code.co_names[param]
            self.global_vars[varname] = val
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x5d: # FOR_ITER
            it = ctx.stack[-1]
            try:
                n = it.__next__()
                print('FOR_ITER', it, n)
                ctx.stack.append(n)
            except StopIteration:
                param = co_code[ctx.pc+1]
                print('FOR_ITER STOP', param)
                ctx.stack.pop()
                if sys.version_info.minor == 8:
                    ctx.pc += param
                elif sys.version_info.minor == 10:
                    ctx.pc += param * 2
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x61: # STORE_GLOBAL
            param = co_code[ctx.pc+1]
            val = ctx.stack.pop()
            global_var = ctx.code.co_names[param]
            # print('STORE_GLOBAL', param, global_var, val)
            self.global_vars[global_var] = val
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x64: # LOAD_CONST
            param = co_code[ctx.pc+1]
            # print('LOAD_CONST', ctx.code.co_consts)
            # print('LOAD_CONST', param, ctx.code.co_consts[param])
            ctx.stack.append(ctx.code.co_consts[param])
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x66: # BUILD_TUPLE
            argc = co_code[ctx.pc+1]
            # print('BUILD_TUPLE', argc)
            # print('BUILD_TUPLE', ctx.code.co_consts)
            # print('BUILD_TUPLE', ctx.stack)
            if argc:
                values = ctx.stack[-argc:]
                ctx.stack = ctx.stack[:-argc]
            else:
                values = []
            ctx.stack.append(tuple(values))
            # print('BUILD_TUPLE', ctx.stack)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x67: # BUILD_LIST
            argc = co_code[ctx.pc+1]
            # print('BUILD_LIST', argc)
            # print('BUILD_LIST', ctx.code.co_consts)
            # print('BUILD_LIST', ctx.stack)
            if argc:
                values = ctx.stack[-argc:]
                ctx.stack = ctx.stack[:-argc]
            else:
                values = []
            ctx.stack.append(list(values))
            # print('BUILD_LIST', ctx.stack)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x69: # BUILD_MAP
            param = co_code[ctx.pc+1]
            # print('BUILD_MAP', param)
            result = {}
            for i in range(param):
                value = ctx.stack.pop()
                key = ctx.stack.pop()
                result[key] = value
            ctx.stack.append(result)
            # print('BUILD_MAP', result)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x6a: # LOAD_ATTR
            param = co_code[ctx.pc+1]
            attr = ctx.code.co_names[param]
            obj = ctx.stack.pop()
            # print('LOAD_ATTR', attr)
            # print('LOAD_ATTR', dir(obj))
            # val = obj.__dict__[attr]
            try:
                val = obj.__getattr__(attr)
            except:
                val = obj.__getattribute__(obj, attr)
            # print('LOAD_ATTR', param, attr, val)
            ctx.stack.append(val)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x6b: # COMPARE_OP
            param = co_code[ctx.pc+1]
            right = ctx.stack.pop()
            left = ctx.stack.pop()
            # print('COMPARE_OP', param, left, right)
            if param == 0:
                ctx.stack.append(left < right)
            elif param == 1:
                ctx.stack.append(left <= right)
            elif param == 2:
                ctx.stack.append(left == right)
            elif param == 3:
                ctx.stack.append(left != right)
            elif param == 4:
                ctx.stack.append(left > right)
            elif param == 5:
                ctx.stack.append(left >= right)
            elif param == 8:
                ctx.stack.append(left is right)

            ctx.pc += 2

        ## MUST DISABLE
        elif co_code[ctx.pc] == 0x6c: # IMPORT_NAME
            raise

        elif co_code[ctx.pc] == 0x6e: # JUMP_FORWARD
            param = co_code[ctx.pc+1]
            # print('JUMP_FORWARD', param)
            ctx.pc += param

        elif co_code[ctx.pc] == 0x71: # JUMP_ABSOLUTE
            param = co_code[ctx.pc+1]
            # print('JUMP_ABSOLUTE', param)
            if sys.version_info.minor == 8:
                ctx.pc = param
            elif sys.version_info.minor == 10:
                ctx.pc = param * 2

        elif co_code[ctx.pc] == 0x72: # POP_JUMP_IF_FALSE
            param = co_code[ctx.pc+1]
            # print('POP_JUMP_IF_FALSE', param)
            val = ctx.stack.pop()
            if val:
                ctx.pc += 2
            else:
                if sys.version_info.minor == 8:
                    ctx.pc = param
                elif sys.version_info.minor == 10:
                    ctx.pc = param * 2

        elif co_code[ctx.pc] == 0x73: # POP_JUMP_IF_TRUE
            param = co_code[ctx.pc+1]
            # print('POP_JUMP_IF_TRUE', param)
            val = ctx.stack.pop()
            if val:
                if sys.version_info.minor == 8:
                    ctx.pc = param
                elif sys.version_info.minor == 10:
                    ctx.pc = param * 2
            else:
                ctx.pc += 2

        elif co_code[ctx.pc] == 0x74: # LOAD_GLOBAL
            param = co_code[ctx.pc+1]
            global_var = ctx.code.co_names[param]
            # print('LOAD_GLOBAL', param, global_var)
            val = self.global_vars[global_var]
            ctx.stack.append(val)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x7a: # SETUP_FINALLY
            param = co_code[ctx.pc+1]
            print('SETUP_FINALLY', param)
            ctx.blocks.append(ctx.pc+param+2)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x7c: # LOAD_FAST
            param = co_code[ctx.pc+1]
            # print('LOAD_FAST', param)
            varname = ctx.code.co_varnames[param]
            val = ctx.local_vars[varname]
            ctx.stack.append(val)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x7d: # STORE_FAST
            param = co_code[ctx.pc+1]
            # print('STORE_FAST', param)
            # print('STORE_FAST', ctx.co_varnames[param])
            var = ctx.code.co_varnames[param]
            val = ctx.stack.pop()
            ctx.local_vars[var] = val
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x82: # RAISE_VARARGS
            param = co_code[ctx.pc+1]
            # print('RAISE_VARARGS', param)
            if param == 1:
                first = ctx.stack.pop()
                raise first
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x83: # CALL_FUNCTION
            param = co_code[ctx.pc+1]
            # print('CALL_FUNCTION', param)
            # print('CALL_FUNCTION', ctx.stack)
            func = ctx.stack[-1-param]
            if param:
                params = ctx.stack[-param:]
            else:
                params = []
            # print('CALL_FUNCTION', func, params)
            result = self.invoke(func, params)
            # print('result', result)
            ctx.stack = ctx.stack[:-1-param]
            ctx.stack.append(result)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x84: # MAKE_FUNCTION
            param = co_code[ctx.pc+1]
            # print('MAKE_FUNCTION', param)
            name = ctx.stack.pop()
            code = ctx.stack.pop()
            func = types.FunctionType(code, self.global_vars, name)
            ctx.stack.append(func)
            print('MAKE_FUNCTION', ctx.stack)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x85: # BUILD_SLICE
            param = co_code[ctx.pc+1]
            # print('BUILD_SLICE', param)

            if param == 1:
                first = ctx.stack.pop()
                ctx.stack.append(slice(first))
            elif param == 2:
                second = ctx.stack.pop()
                first = ctx.stack.pop()
                ctx.stack.append(slice(first, second))
            elif param == 3:
                third = ctx.stack.pop()
                second = ctx.stack.pop()
                first = ctx.stack.pop()
                ctx.stack.append(slice(first, second, third))
            ctx.pc += 2

        # elif co_code[ctx.pc] == 0x86: # JUMP_BACKWARD_NO_INTERRUPT
        #     pass
        # elif co_code[ctx.pc] == 0x87: # MAKE_CELL
        #     pass
        # elif co_code[ctx.pc] == 0x88: # LOAD_CLOSURE
        #     pass
        # elif co_code[ctx.pc] == 0x89: # LOAD_DEREF
        #     pass
        # elif co_code[ctx.pc] == 0x8a: # STORE_DEREF
        #     pass
        # elif co_code[ctx.pc] == 0x8b: # DELETE_DEREF
        #     pass
        # elif co_code[ctx.pc] == 0x8c: # JUMP_BACKWARD
        #     pass

        elif co_code[ctx.pc] == 0x8d: # CALL_FUNCTION_KW
            argc = co_code[ctx.pc+1]
            # print('CALL_FUNCTION_KW', ctx.stack)
            keys = ctx.stack.pop()
            values = ctx.stack[-argc:]
            ctx.stack = ctx.stack[:-argc]
            obj = ctx.stack.pop()
            # print('CALL_FUNCTION_KW', obj)
            # print('CALL_FUNCTION_KW', dir(obj))
            val = obj(**dict(zip(keys, values)))
            ctx.stack.append(val)
            # print('CALL_FUNCTION_KW', val)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x8e: # CALL_FUNCTION_EX
            argc = co_code[ctx.pc+1]
            # print('CALL_FUNCTION_EX', argc)
            kargs = ctx.stack.pop()
            args = ctx.stack.pop()
            obj = ctx.stack.pop()
            val = obj(*args, **kargs)
            ctx.stack.append(val)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x8f: # SETUP_WITH
            param = co_code[ctx.pc+1]
            print('SETUP_WITH', param)

            obj = ctx.stack.pop()
            enter = obj.__enter__()
            print('SETUP_WITH', enter)

            ctx.stack.append(ctx.pc + param + 2)
            ctx.stack.append(enter)
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x9b: # FORMAT_VALUE
            param = co_code[ctx.pc+1]
            format_string = ctx.stack.pop()
            val = ctx.stack.pop()
            ctx.stack.append(format(val, format_string))
            ctx.pc += 2

        elif co_code[ctx.pc] == 0x9d: # BUILD_STRING
            argc = co_code[ctx.pc+1]
            # print('BUILD_STRING', argc)
            values = ctx.stack[-argc:]
            ctx.stack = ctx.stack[:-argc]
            ctx.stack.append(''.join(values))
            ctx.pc += 2

        elif co_code[ctx.pc] == 0xa0: # LOAD_METHOD
            param = co_code[ctx.pc+1]
            # print('LOAD_METHOD', param)
            ctx.stack.append(ctx.code.co_names[param])
            ctx.pc += 2

        elif co_code[ctx.pc] == 0xa1: # CALL_METHOD
            param = co_code[ctx.pc+1]
            # print('CALL_METHOD', param)
            # print('CALL_METHOD', ctx.stack)
            obj = ctx.stack[-2-param]
            #print('CALL_METHOD', dir(obj))
            method = ctx.stack[-1-param]
            if param:
                params = ctx.stack[-param:]
            else:
                params = []
            # print('CALL_METHOD', method)
            # print('CALL_METHOD', params)
            # print('CALL_METHOD', obj.__getattribute__(method))
            if type(obj) == type:
                method_obj = obj.__dict__[method]
                call_obj = method_obj.__get__(obj)
                # print('CALL_METHOD', obj.__dict__[method])
                result = functools.partial(call_obj, *params)()
            else:
                try:
                    result = functools.partial(obj.__getattribute__(method), *params)()
                except AttributeError:
                    result = functools.partial(obj.__getattr__(method), *params)()

            # print('CALL_METHOD result', result)
            ctx.stack = ctx.stack[:-2-param]
            ctx.stack.append(result)
            ctx.pc += 2

        # print('stack', ctx.stack)
        # print('---')
