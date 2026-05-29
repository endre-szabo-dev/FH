#!/usr/bin/env ruby bench.rb

def rand01(seed_ref)
  x = seed_ref[0] & 0xFFFFFFFF
  x ^= ((x << 13) & 0xFFFFFFFF)
  x ^= (x >> 17)
  x ^= ((x << 5) & 0xFFFFFFFF)
  seed_ref[0] = x & 0xFFFFFFFF
  (x & 0xFFFFFF) / 16777216.0
end

def i32(x)
  x.to_i
end

def make_tilemap(w, h, seed_ref)
  tiles = []
  (w * h).times do
    t = 0
    t = 1 if rand01(seed_ref) < 0.18
    tiles << t
  end
  { "w" => w, "h" => h, "tiles" => tiles }
end

def tile_at(tiles, w, h, x, y)
  return 1 if x < 0 || y < 0
  return 1 if x >= w || y >= h
  tiles[y * w + x]
end

def aabb_hits_solid(tiles, w, h, x, y, ew, eh)
  x0 = i32(x)
  y0 = i32(y)
  x1 = i32(x + ew)
  y1 = i32(y + eh)

  return true if tile_at(tiles, w, h, x0, y0) == 1
  return true if tile_at(tiles, w, h, x1, y0) == 1
  return true if tile_at(tiles, w, h, x0, y1) == 1
  return true if tile_at(tiles, w, h, x1, y1) == 1
  false
end

def spawn_entity(seed, w, h, xs, ys, vxs, vys, ws, hs, on_gs, ais, lifes)
  xs << (rand01(seed) * (w - 2) + 1)
  ys << (rand01(seed) * (h - 2) + 1)
  vxs << ((rand01(seed) - 0.5) * 6.0)
  vys << ((rand01(seed) - 0.5) * 2.0)
  ws << 0.9
  hs << 0.9
  on_gs << false
  ais << (rand01(seed) < 0.25)
  lifes << (300.0 + (rand01(seed) * 600.0))
end

def bench(frames, entities, spawn_per_frame)
  seed = [123456789]
  map = make_tilemap(128, 72, seed)
  w = map["w"]
  h = map["h"]
  tiles = map["tiles"]

  xs = []; ys = []; vxs = []; vys = []
  ws = []; hs = []; on_gs = []; ais = []; lifes = []

  i = 0
  while i < entities
    spawn_entity(seed, w, h, xs, ys, vxs, vys, ws, hs, on_gs, ais, lifes)
    i += 1
  end

  dt = 1.0 / 60.0
  checksum = 0.0

  active_len = xs.length

  f = 0
  while f < frames
    s = 0
    while s < spawn_per_frame
      spawn_entity(seed, w, h, xs, ys, vxs, vys, ws, hs, on_gs, ais, lifes)
      s += 1
    end

    active_len += spawn_per_frame

    write = 0
    n = 0
    while n < active_len
      x = xs[n]
      y = ys[n]
      vx = vxs[n]
      vy = vys[n]
      ew = ws[n]
      eh = hs[n]
      on_g = on_gs[n]
      ai = ais[n]
      life = lifes[n]

      vy = vy + 18.0 * dt

      if ai
        dir = (vx >= 0.0) ? 1 : -1
        ahead_x = i32(x + dir.to_f)
        foot_y = i32(y + 1.0)
        vx = -vx if tile_at(tiles, w, h, ahead_x, foot_y) == 0
      end

      new_x = x + vx * dt
      if !aabb_hits_solid(tiles, w, h, new_x, y, ew, eh)
        x = new_x
      else
        vx = -vx * 0.3
      end

      new_y = y + vy * dt
      if !aabb_hits_solid(tiles, w, h, x, new_y, ew, eh)
        y = new_y
        on_g = false
      else
        on_g = true if vy > 0.0
        vy = 0.0
      end

      vx = vx * (1.0 - 8.0 * dt) if on_g

      life = life - 1.0
      checksum = checksum + x + y + vx + vy

      if life > 0.0
        xs[write] = x
        ys[write] = y
        vxs[write] = vx
        vys[write] = vy
        ws[write] = ew
        hs[write] = eh
        on_gs[write] = on_g
        ais[write] = ai
        lifes[write] = life
        write += 1
      end

      n += 1
    end

    active_len = write
    f += 1
  end

  puts format('%.6f', checksum)
end

def main
  bench(3600, 300, 3)
end

main if __FILE__ == $0