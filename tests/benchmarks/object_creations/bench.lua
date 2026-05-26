local function bench_objects(N)
  local v = {}

  -- alloc_only
  for i = 0, N - 1 do
    v[i + 1] = { x = i, y = i + 1, z = i + 2, next = nil }
  end

  -- link
  for i = 1, N - 1 do
    v[i].next = v[i + 1]
  end

  -- mutate + checksum
  local checksum = 0.0
  for i = 1, N do
    local o = v[i]
    o.x = o.x + 1
    o.y = o.y + 2
    o.z = o.z + 3
    checksum = checksum + o.x + o.y + o.z
  end

  -- alloc_churn
  local keep = {}
  for i = 0, (N * 3) - 1 do
    local t = { a = i, b = i + 1, c = i + 2 }
    if (i % 10) == 0 then
      keep[#keep + 1] = t
    end
  end

  print(checksum + #v + #keep)
end

bench_objects(1000000)