function calc_point(cx, cy, max_iter)
  local i, x, y = 0, 0.0, 0.0
  while i < max_iter do
    local t = x*x - y*y + cx
    y = 2*x*y + cy
    x = t
    if x*x + y*y > 4.0 then break end
    i = i + 1
  end
  return i
end

function mandelbrot(x1,y1,x2,y2,size_x,size_y,max_iter)
  local step_x = (x2-x1)/(size_x-1)
  local step_y = (y2-y1)/(size_y-1)
  local checksum = 0

  local y = y1
  for yi = 0, size_y-1 do
    local x = x1
    for xi = 0, size_x-1 do
      checksum = checksum + calc_point(x, y, max_iter)
      x = x + step_x
    end
    y = y + step_y
  end

  return checksum
end

local s = mandelbrot(-2, -2, 2, 2, 500, 500, 1500)
print(s)