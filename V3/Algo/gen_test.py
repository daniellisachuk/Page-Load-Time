
def gen():
    for i, c in enumerate("abcdefghij"):
        yield i, c


if __name__ == '__main__':
    gen = gen()
    print(next(gen))
    print(next(gen))
    print(next(gen))
    print(next(gen))
    print(next(gen))