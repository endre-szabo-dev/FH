-- bench_call.lua
local function f(x)
  return x
end

local i = 0
while i < 200000000 do
  f(i)
  i = i + 1
end
print(i)