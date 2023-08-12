
import traceback


def log(*t):
    funcs = []
    for line in traceback.format_stack():
        func = line.split('\n')[1].strip()
        funcs.append(func)
    print('> '+'\n> '.join(funcs[:-2]))
    print(*t)
    print()

