# bench_call.py
def f(x):
    return x

i = 0
while i < 200_000_000:
    f(i)
    i += 1

print(i)