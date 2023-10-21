
import sys
import functools
import types

assert sys.version_info.major == 3

class VM:
    '''for python 3.10'''

    def __init__(self):
        self.module_object = None
        self.co_code = None

        self.local_vars = {}
        self.global_vars = {}

    def import_function(self, function_object, global_vars = {}):
        self.co_code = function_object.__code__.co_code
        self.co_varnames = function_object.__code__.co_varnames
        self.co_consts = function_object.__code__.co_consts
        self.co_names = function_object.__code__.co_names
        self.co_argcount = function_object.__code__.co_argcount

        if global_vars:
            self.global_vars = global_vars

    def import_module(self, module_object):
        for k, v in module_object.__dict__.items():
            if not k.startswith('__') and type(v) not in [type, types.FunctionType]:
                self.global_vars[k] = v

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
        self.module_object = module_object

    def run(self, args, function_name = None):
        self.pc = 0
        self.stack = []
        self.blocks = []

        if self.module_object and function_name:
            function_object = self.module_object.__dict__[function_name]
            assert type(function_object) == types.FunctionType
            self.import_function(function_object)

        assert self.co_code
        # assert self.co_varnames
        # assert self.co_consts
        # assert self.co_names
        assert self.co_argcount == len(args)
        self.args = args
        for i, v in enumerate(self.args):
            self.local_vars[self.co_varnames[i]] = v

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
        while pc != self.pc:
            pc = self.pc
            # try:
            r = self.step()
            if r is not None:
                print('return value', r)
                return r
            # except BaseException as e:
            #     print('except', e.__class__.__name__, dir(e.__class__))
            #     print('blocks', self.blocks)
            #     if self.blocks:
            #         new_pc = self.blocks[-1]
            #         self.pc = new_pc
            # print('stack', self.stack)
        # print('---')
        # print('global_vars', self.global_vars)
        return False

    def step(self):
        # print('PC', self.pc, hex(self.co_code[self.pc]))
        # print('local_vars', self.local_vars)
        if self.co_code[self.pc] == 0x0: # NOP
            print('NOP')

        elif self.co_code[self.pc] == 0x1: # POP_TOP
            # print('POP_TOP')
            self.stack.pop()
            self.pc += 2

        elif self.co_code[self.pc] == 0x2: # ROT_TWO
            # print('ROT_TWO')
            first = self.stack.pop()
            second = self.stack.pop()
            self.stack.append(first)
            self.stack.append(second)
            self.pc += 2

        elif self.co_code[self.pc] == 0x3: # ROT_THREE
            # print('ROT_THREE')
            first = self.stack.pop()
            second = self.stack.pop()
            third = self.stack.pop()
            self.stack.append(first)
            self.stack.append(third)
            self.stack.append(second)
            self.pc += 2

        elif self.co_code[self.pc] == 0x4: # DUP_TOP
            # print('DUP_TOP')
            first = self.stack[-1]
            self.stack.append(first)
            self.pc += 2

        elif self.co_code[self.pc] == 0x5: # DUP_TOP_TWO
            # print('DUP_TOP_TWO')
            second = self.stack[-2]
            first = self.stack[-1]
            self.stack.append(second)
            self.stack.append(first)
            self.pc += 2

        elif self.co_code[self.pc] == 0x13: # BINARY_POWER
            exp = self.stack.pop()
            base = self.stack.pop()
            # print('BINARY_POWER', base, exp)
            self.stack.append(base ** exp)
            self.pc += 2

        elif self.co_code[self.pc] == 0x14: # BINARY_MULTIPLY
            right = self.stack.pop()
            left = self.stack.pop()
            # print('BINARY_MULTIPLY', left, right)
            self.stack.append(left*right)
            self.pc += 2

        elif self.co_code[self.pc] == 0x16: # BINARY_MODULO
            right = self.stack.pop()
            left = self.stack.pop()
            # print('BINARY_MODULO', left, right)
            self.stack.append(left%right)
            self.pc += 2

        elif self.co_code[self.pc] == 0x17: # BINARY_ADD
            right = self.stack.pop()
            left = self.stack.pop()
            # print('BINARY_ADD', left, right)
            self.stack.append(left+right)
            self.pc += 2

        elif self.co_code[self.pc] == 0x18: # BINARY_SUBTRACT
            right = self.stack.pop()
            left = self.stack.pop()
            # print('BINARY_SUBTRACT', left, right)
            self.stack.append(left-right)
            self.pc += 2

        elif self.co_code[self.pc] == 0x19: # BINARY_SUBSCR
            idx = self.stack.pop()
            obj = self.stack.pop()
            self.stack.append(obj[idx])
            # print('BINARY_SUBSCR')
            self.pc += 2

        elif self.co_code[self.pc] == 0x1a: # BINARY_FLOOR_DIVIDE
            right = self.stack.pop()
            left = self.stack.pop()
            # print('BINARY_FLOOR_DIVIDE', left, right)
            self.stack.append(left//right)
            self.pc += 2

        elif self.co_code[self.pc] == 0x1b: # BINARY_TRUE_DIVIDE
            right = self.stack.pop()
            left = self.stack.pop()
            # print('BINARY_TRUE_DIVIDE', left, right)
            self.stack.append(left/right)
            self.pc += 2

        elif self.co_code[self.pc] == 0x37: # INPLACE_ADD
            val = self.stack.pop()
            obj = self.stack.pop()
            # print('INPLACE_ADD', obj, '+=', val)

            self.stack.append(obj + val)
            self.pc += 2

        elif self.co_code[self.pc] == 0x38: # INPLACE_SUBTRACT
            val = self.stack.pop()
            obj = self.stack.pop()
            # print('INPLACE_SUBTRACT', obj, '-=', val)

            self.stack.append(obj - val)
            self.pc += 2

        elif self.co_code[self.pc] == 0x3c: # STORE_SUBSCR
            key = self.stack.pop()
            obj = self.stack.pop()
            val = self.stack.pop()
            # print('STORE_SUBSCR', obj, '[', key, '] =', val)

            obj[key] = val
            self.pc += 2

        elif self.co_code[self.pc] == 0x44: # GET_ITER
            val = self.stack.pop()
            self.stack.append(iter(val))
            self.pc += 2

        elif self.co_code[self.pc] == 0x51: # WITH_CLEANUP_START
            # val = self.stack.pop()
            # print('WITH_CLEANUP_START')
            self.pc += 2

        elif self.co_code[self.pc] == 0x52: # WITH_CLEANUP_FINISH
            # val = self.stack.pop()
            # print('WITH_CLEANUP_FINISH')
            self.pc += 2

        elif self.co_code[self.pc] == 0x53: # RETURN_VALUE
            val = self.stack.pop()
            # print('RETURN_VALUE', val)
            return val

        elif self.co_code[self.pc] == 0x57: # POP_BLOCK
            # param = self.co_code[self.pc+1]
            delta = self.blocks.pop()
            print('POP_BLOCK', delta)
            self.pc += 2

        elif self.co_code[self.pc] == 0x58: # END_FINALLY
            # print('END_FINALLY')
            self.pc += 2

        elif self.co_code[self.pc] == 0x59: # POP_EXCEPT
            print('POP_EXCEPT')
            print('blocks', self.blocks)
            self.blocks.pop()
            self.pc += 2

        elif self.co_code[self.pc] == 0x5d: # FOR_ITER
            it = self.stack[-1]
            try:
                n = it.__next__()
                print('FOR_ITER', it, n)
                self.stack.append(n)
            except StopIteration:
                param = self.co_code[self.pc+1]
                print('FOR_ITER STOP', param)
                self.stack.pop()
                if sys.version_info.minor == 8:
                    self.pc += param
                elif sys.version_info.minor == 10:
                    self.pc += param * 2
            self.pc += 2

        elif self.co_code[self.pc] == 0x61: # STORE_GLOBAL
            param = self.co_code[self.pc+1]
            val = self.stack.pop()
            global_var = self.co_names[param]
            # print('STORE_GLOBAL', param, global_var, val)
            self.global_vars[global_var] = val
            self.pc += 2

        elif self.co_code[self.pc] == 0x64: # LOAD_CONST
            param = self.co_code[self.pc+1]
            # print('LOAD_CONST', self.co_consts)
            # print('LOAD_CONST', param, self.co_consts[param])
            self.stack.append(self.co_consts[param])
            self.pc += 2

        elif self.co_code[self.pc] == 0x66: # BUILD_TUPLE
            argc = self.co_code[self.pc+1]
            # print('BUILD_TUPLE', argc)
            # print('BUILD_TUPLE', self.co_consts)
            # print('BUILD_TUPLE', self.stack)
            if argc:
                values = self.stack[-argc:]
                self.stack = self.stack[:-argc]
            else:
                values = []
            self.stack.append(tuple(values))
            # print('BUILD_TUPLE', self.stack)
            self.pc += 2

        elif self.co_code[self.pc] == 0x67: # BUILD_LIST
            argc = self.co_code[self.pc+1]
            # print('BUILD_LIST', argc)
            # print('BUILD_LIST', self.co_consts)
            # print('BUILD_LIST', self.stack)
            if argc:
                values = self.stack[-argc:]
                self.stack = self.stack[:-argc]
            else:
                values = []
            self.stack.append(list(values))
            # print('BUILD_LIST', self.stack)
            self.pc += 2

        elif self.co_code[self.pc] == 0x69: # BUILD_MAP
            param = self.co_code[self.pc+1]
            # print('BUILD_MAP', param)
            result = {}
            for i in range(param):
                value = self.stack.pop()
                key = self.stack.pop()
                result[key] = value
            self.stack.append(result)
            # print('BUILD_MAP', result)
            self.pc += 2

        elif self.co_code[self.pc] == 0x6a: # LOAD_ATTR
            param = self.co_code[self.pc+1]
            attr = self.co_names[param]
            obj = self.stack.pop()
            # print('LOAD_ATTR', attr)
            # print('LOAD_ATTR', dir(obj))
            # val = obj.__dict__[attr]
            # val = obj.__getattribute__(attr)
            val = obj.__getattr__(attr)
            # print('LOAD_ATTR', param, attr, val)
            self.stack.append(val)
            self.pc += 2

        elif self.co_code[self.pc] == 0x6b: # COMPARE_OP
            param = self.co_code[self.pc+1]
            right = self.stack.pop()
            left = self.stack.pop()
            # print('COMPARE_OP', param, left, right)
            if param == 0:
                self.stack.append(left < right)
            elif param == 1:
                self.stack.append(left <= right)
            elif param == 2:
                self.stack.append(left == right)
            elif param == 3:
                self.stack.append(left != right)
            elif param == 4:
                self.stack.append(left > right)
            elif param == 5:
                self.stack.append(left >= right)
            elif param == 8:
                self.stack.append(left is right)

            self.pc += 2

        # elif self.co_code[self.pc] == 0x6c: # IMPORT_NAME
        #     param = self.co_code[self.pc+1]
        #     self.pc += 2

        elif self.co_code[self.pc] == 0x6e: # JUMP_FORWARD
            param = self.co_code[self.pc+1]
            # print('JUMP_FORWARD', param)
            self.pc += param

        elif self.co_code[self.pc] == 0x71: # JUMP_ABSOLUTE
            param = self.co_code[self.pc+1]
            print('JUMP_ABSOLUTE', param)
            if sys.version_info.minor == 8:
                self.pc = param
            elif sys.version_info.minor == 10:
                self.pc = param * 2

        elif self.co_code[self.pc] == 0x72: # POP_JUMP_IF_FALSE
            param = self.co_code[self.pc+1]
            # print('POP_JUMP_IF_FALSE', param)
            val = self.stack.pop()
            if val:
                self.pc += 2
            else:
                if sys.version_info.minor == 8:
                    self.pc = param
                elif sys.version_info.minor == 10:
                    self.pc = param * 2

        elif self.co_code[self.pc] == 0x73: # POP_JUMP_IF_TRUE
            param = self.co_code[self.pc+1]
            # print('POP_JUMP_IF_TRUE', param)
            val = self.stack.pop()
            if val:
                if sys.version_info.minor == 8:
                    self.pc = param
                elif sys.version_info.minor == 10:
                    self.pc = param * 2
            else:
                self.pc += 2

        elif self.co_code[self.pc] == 0x74: # LOAD_GLOBAL
            param = self.co_code[self.pc+1]
            global_var = self.co_names[param]
            # print('LOAD_GLOBAL', param, global_var)
            val = self.global_vars[global_var]
            self.stack.append(val)
            self.pc += 2

        elif self.co_code[self.pc] == 0x7a: # SETUP_FINALLY
            param = self.co_code[self.pc+1]
            print('SETUP_FINALLY', param)
            self.blocks.append(self.pc+param+2)
            self.pc += 2

        elif self.co_code[self.pc] == 0x7c: # LOAD_FAST
            param = self.co_code[self.pc+1]
            # print('LOAD_FAST', param)
            varname = self.co_varnames[param]
            val = self.local_vars[varname]
            self.stack.append(val)
            self.pc += 2

        elif self.co_code[self.pc] == 0x7d: # STORE_FAST
            param = self.co_code[self.pc+1]
            # print('STORE_FAST', param)
            # print('STORE_FAST', self.co_varnames[param])
            var = self.co_varnames[param]
            val = self.stack.pop()
            self.local_vars[var] = val
            self.pc += 2

        elif self.co_code[self.pc] == 0x82: # RAISE_VARARGS
            param = self.co_code[self.pc+1]
            # print('RAISE_VARARGS', param)
            if param == 1:
                first = self.stack.pop()
                raise first
            self.pc += 2

        elif self.co_code[self.pc] == 0x83: # CALL_FUNCTION
            param = self.co_code[self.pc+1]
            # print('CALL_FUNCTION', param)
            func = self.stack[-1-param]
            params = self.stack[-param:]
            result = functools.partial(func, *params)()
            # print('result', result)
            self.stack = self.stack[:-1-param]
            self.stack.append(result)
            self.pc += 2

        elif self.co_code[self.pc] == 0x85: # BUILD_SLICE
            param = self.co_code[self.pc+1]
            # print('BUILD_SLICE', param)

            if param == 1:
                first = self.stack.pop()
                self.stack.append(slice(first))
            elif param == 2:
                second = self.stack.pop()
                first = self.stack.pop()
                self.stack.append(slice(first, second))
            elif param == 3:
                third = self.stack.pop()
                second = self.stack.pop()
                first = self.stack.pop()
                self.stack.append(slice(first, second, third))
            self.pc += 2

        # elif self.co_code[self.pc] == 0x86: # JUMP_BACKWARD_NO_INTERRUPT
        #     pass
        # elif self.co_code[self.pc] == 0x87: # MAKE_CELL
        #     pass
        # elif self.co_code[self.pc] == 0x88: # LOAD_CLOSURE
        #     pass
        # elif self.co_code[self.pc] == 0x89: # LOAD_DEREF
        #     pass
        # elif self.co_code[self.pc] == 0x8a: # STORE_DEREF
        #     pass
        # elif self.co_code[self.pc] == 0x8b: # DELETE_DEREF
        #     pass
        # elif self.co_code[self.pc] == 0x8c: # JUMP_BACKWARD
        #     pass

        elif self.co_code[self.pc] == 0x8d: # CALL_FUNCTION_KW
            argc = self.co_code[self.pc+1]
            # print('CALL_FUNCTION_KW', self.stack)
            keys = self.stack.pop()
            values = self.stack[-argc:]
            self.stack = self.stack[:-argc]
            obj = self.stack.pop()
            # print('CALL_FUNCTION_KW', obj)
            # print('CALL_FUNCTION_KW', dir(obj))
            val = obj(**dict(zip(keys, values)))
            self.stack.append(val)
            # print('CALL_FUNCTION_KW', val)
            self.pc += 2

        elif self.co_code[self.pc] == 0x8e: # CALL_FUNCTION_EX
            argc = self.co_code[self.pc+1]
            # print('CALL_FUNCTION_EX', argc)
            kargs = self.stack.pop()
            args = self.stack.pop()
            obj = self.stack.pop()
            val = obj(*args, **kargs)
            self.stack.append(val)
            self.pc += 2

        elif self.co_code[self.pc] == 0x8f: # SETUP_WITH
            param = self.co_code[self.pc+1]
            print('SETUP_WITH', param)

            obj = self.stack.pop()
            enter = obj.__enter__()
            print('SETUP_WITH', enter)

            self.stack.append(self.pc + param + 2)
            self.stack.append(enter)
            self.pc += 2

        elif self.co_code[self.pc] == 0x9b: # FORMAT_VALUE
            param = self.co_code[self.pc+1]
            format_string = self.stack.pop()
            val = self.stack.pop()
            self.stack.append(format(val, format_string))
            self.pc += 2

        elif self.co_code[self.pc] == 0x9d: # BUILD_STRING
            argc = self.co_code[self.pc+1]
            # print('BUILD_STRING', argc)
            values = self.stack[-argc:]
            self.stack = self.stack[:-argc]
            self.stack.append(''.join(values))
            self.pc += 2

        elif self.co_code[self.pc] == 0xa0: # LOAD_METHOD
            param = self.co_code[self.pc+1]
            # print('LOAD_METHOD', param)
            self.stack.append(self.co_names[param])
            self.pc += 2

        elif self.co_code[self.pc] == 0xa1: # CALL_METHOD
            param = self.co_code[self.pc+1]
            # print('CALL_METHOD', param)
            # print('CALL_METHOD', self.stack)
            obj = self.stack[-2-param]
            # print('CALL_METHOD', obj)
            method = self.stack[-1-param]
            # print('CALL_METHOD', method)
            if param:
                params = self.stack[-param:]
            else:
                params = []
            # print('CALL_METHOD', obj.__getattribute__(method))
            try:
                result = functools.partial(obj.__getattribute__(method), *params)()
            except AttributeError:
                result = functools.partial(obj.__getattr__(method), *params)()

            # print('CALL_METHOD result', result)
            self.stack = self.stack[:-2-param]
            self.stack.append(result)
            self.pc += 2

        # print('stack', self.stack)
        # print('---')
