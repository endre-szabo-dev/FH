def bench_objects(n)
  v = []

  # alloc_only
  i = 0
  while i < n
    v << { "x" => i, "y" => i + 1, "z" => i + 2, "next" => nil }
    i += 1
  end

  # link
  i = 0
  while i < n - 1
    v[i]["next"] = v[i + 1]
    i += 1
  end

  # mutate + checksum
  checksum = 0.0
  i = 0
  while i < n
    o = v[i]
    o["x"] = o["x"] + 1
    o["y"] = o["y"] + 2
    o["z"] = o["z"] + 3
    checksum += o["x"] + o["y"] + o["z"]
    i += 1
  end

  # alloc_churn
  keep = []
  i = 0
  while i < n * 3
    t = { "a" => i, "b" => i + 1, "c" => i + 2 }
    keep << t if (i % 10) == 0
    i += 1
  end

  puts(checksum + v.length + keep.length)
end

bench_objects(1_000_000)