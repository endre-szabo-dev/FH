#!/usr/bin/env python3 bench.py

from __future__ import annotations
from typing import List, Dict, Any


def rand01(seed_ref: List[int]) -> float:
    # xorshift32 -> [0,1)
    x = seed_ref[0] & 0xFFFFFFFF
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= (x >> 17) & 0xFFFFFFFF
    x ^= (x << 5) & 0xFFFFFFFF
    seed_ref[0] = x
    # 24-bit mantissa-ish fraction
    return (x & 0xFFFFFF) / 16777216.0


def i32(x: float) -> int:
    # FH benchmark intended integer conversion
    return int(x)


def make_tilemap(w: int, h: int, seed_ref: List[int]) -> Dict[str, Any]:
    tiles: List[int] = []
    for _ in range(w * h):
        t = 0
        if rand01(seed_ref) < 0.18:
            t = 1
        tiles.append(t)
    return {"w": w, "h": h, "tiles": tiles}


def tile_at(tiles: List[int], w: int, h: int, x: int, y: int) -> int:
    if x < 0 or y < 0:
        return 1
    if x >= w or y >= h:
        return 1
    return tiles[y * w + x]


def aabb_hits_solid(tiles: List[int], w: int, h: int, x: float, y: float, ew: float, eh: float) -> bool:
    x0 = i32(x)
    y0 = i32(y)
    x1 = i32(x + ew)
    y1 = i32(y + eh)
    if tile_at(tiles, w, h, x0, y0) == 1:
        return True
    if tile_at(tiles, w, h, x1, y0) == 1:
        return True
    if tile_at(tiles, w, h, x0, y1) == 1:
        return True
    if tile_at(tiles, w, h, x1, y1) == 1:
        return True
    return False


def spawn_entity(
    seed: List[int],
    w: int,
    h: int,
    xs: List[float],
    ys: List[float],
    vxs: List[float],
    vys: List[float],
    ws: List[float],
    hs: List[float],
    onGs: List[bool],
    ais: List[bool],
    lifes: List[float],
) -> None:
    xs.append(rand01(seed) * (w - 2) + 1)
    ys.append(rand01(seed) * (h - 2) + 1)
    vxs.append((rand01(seed) - 0.5) * 6.0)
    vys.append((rand01(seed) - 0.5) * 2.0)
    ws.append(0.9)
    hs.append(0.9)
    onGs.append(False)
    ais.append(rand01(seed) < 0.25)
    lifes.append(300.0 + (rand01(seed) * 600.0))


def bench(frames: int, entities: int, spawnPerFrame: int) -> None:
    seed = [123456789]
    m = make_tilemap(128, 72, seed)
    w = int(m["w"])
    h = int(m["h"])
    tiles: List[int] = m["tiles"]

    xs: List[float] = []
    ys: List[float] = []
    vxs: List[float] = []
    vys: List[float] = []
    ws: List[float] = []
    hs: List[float] = []
    onGs: List[bool] = []
    ais: List[bool] = []
    lifes: List[float] = []

    i = 0
    while i < entities:
        spawn_entity(seed, w, h, xs, ys, vxs, vys, ws, hs, onGs, ais, lifes)
        i += 1

    dt = 1.0 / 60.0
    checksum = 0.0

    active_len = len(xs)

    f = 0
    while f < frames:
        s = 0
        while s < spawnPerFrame:
            spawn_entity(seed, w, h, xs, ys, vxs, vys, ws, hs, onGs, ais, lifes)
            s += 1

        # only the freshly spawned entities extend the active length
        active_len += spawnPerFrame

        write = 0
        n = 0

        while n < active_len:
            x = xs[n]
            y = ys[n]
            vx = vxs[n]
            vy = vys[n]
            ew = ws[n]
            eh = hs[n]
            onG = onGs[n]
            ai = ais[n]
            life = lifes[n]

            vy = vy + 18.0 * dt

            if ai:
                dir_ = -1
                if vx >= 0.0:
                    dir_ = 1
                aheadX = i32(x + float(dir_))
                footY = i32(y + 1.0)
                if tile_at(tiles, w, h, aheadX, footY) == 0:
                    vx = -vx

            newX = x + vx * dt
            if not aabb_hits_solid(tiles, w, h, newX, y, ew, eh):
                x = newX
            else:
                vx = -vx * 0.3

            newY = y + vy * dt
            if not aabb_hits_solid(tiles, w, h, x, newY, ew, eh):
                y = newY
                onG = False
            else:
                if vy > 0.0:
                    onG = True
                vy = 0.0

            if onG:
                vx = vx * (1.0 - 8.0 * dt)

            life = life - 1.0
            checksum = checksum + x + y + vx + vy

            if life > 0.0:
                # in-place compaction across ALL arrays
                xs[write] = x
                ys[write] = y
                vxs[write] = vx
                vys[write] = vy
                ws[write] = ew
                hs[write] = eh
                onGs[write] = onG
                ais[write] = ai
                lifes[write] = life
                write += 1

            n += 1

        # new active length is the compacted count
        active_len = write

        f += 1

    print(f"{checksum:.6f}")


def main() -> None:
    bench(3600, 300, 3)


if __name__ == "__main__":
    main()