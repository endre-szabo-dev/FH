def bench_objects(N: int) -> None:
    v = []

    # alloc_only
    for i in range(N):
        v.append({"x": i, "y": i + 1, "z": i + 2, "next": None})

    # link
    for i in range(N - 1):
        v[i]["next"] = v[i + 1]

    # mutate + checksum
    checksum = 0.0
    for i in range(N):
        o = v[i]
        o["x"] = o["x"] + 1
        o["y"] = o["y"] + 2
        o["z"] = o["z"] + 3
        checksum += o["x"] + o["y"] + o["z"]

    # alloc_churn
    keep = []
    for i in range(N * 3):
        t = {"a": i, "b": i + 1, "c": i + 2}
        if (i % 10) == 0:
            keep.append(t)

    print(checksum + len(v) + len(keep))


if __name__ == "__main__":
    bench_objects(1_000_000)