# @Author   : xiansong wu
# @Time     : 2021/12/29 15:12
# @Function :

import os
import sys
import importlib


def a(func):
    def wrapper(*args, **kwargs):
        print("a")
        print(args[0])
        print(kwargs)
        return func(*args, **kwargs)
    return wrapper

@a
def b(ar):
    print(ar)

if __name__ == "__main__":
    token = importlib.import_module(".tokens.redis", token)
    token.mk_token()


