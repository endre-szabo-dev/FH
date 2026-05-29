# bench_call.rb
def f(x)
  x
end

i = 0
while i < 200_000_000
  f(i)
  i += 1
end
  puts i