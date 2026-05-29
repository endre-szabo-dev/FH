def calc_point(cx, cy, max_iter)
  i = 0
  x = 0.0
  y = 0.0
  while i < max_iter
    t = x*x - y*y + cx
    y = 2.0*x*y + cy
    x = t
    break if x*x + y*y > 4.0
    i += 1
  end
  i
end

def mandelbrot(x1,y1,x2,y2,size_x,size_y,max_iter)
  # force float math
  x1 = x1.to_f
  y1 = y1.to_f
  x2 = x2.to_f
  y2 = y2.to_f

  step_x = (x2 - x1) / (size_x - 1).to_f
  step_y = (y2 - y1) / (size_y - 1).to_f

  checksum = 0
  y = y1

  size_y.times do
    x = x1
    size_x.times do
      checksum += calc_point(x, y, max_iter)
      x += step_x
    end
    y += step_y
  end

  checksum
end

s = mandelbrot(-2, -2, 2, 2, 500, 500, 1500)
puts s