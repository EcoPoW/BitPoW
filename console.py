
#import traceback
import inspect

def log(*t):
    print()
    #print(inspect.stack()[1])
    #print(inspect.stack()[1].frame)
    print(inspect.stack()[1].function, inspect.stack()[1].filename+':', inspect.stack()[1].lineno)
    #funcs = []
    #for line in traceback.format_stack():
    #    func = line.split('\n')[1].strip()
    #    funcs.append(func)
    #print('> '+'\n> '.join(funcs[:-2]))
    print(*t)

def prt(*t):
    print()
    print(inspect.stack()[1].function+':', *t)

