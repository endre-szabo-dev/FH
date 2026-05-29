def calc_point(cx: float, cy: float, max_iter: int) -> int:
    i = 0
    x = 0.0
    y = 0.0
    while i < max_iter:
        t = x*x - y*y + cx
        y = 2.0*x*y + cy
        x = t
        if x*x + y*y > 4.0:
            break
        i += 1
    return i

def mandelbrot(x1, y1, x2, y2, size_x, size_y, max_iter) -> int:
    step_x = (x2 - x1) / (size_x - 1)
    step_y = (y2 - y1) / (size_y - 1)
    checksum = 0

    y = y1
    for _yi in range(size_y):
        x = x1
        for _xi in range(size_x):
            checksum += calc_point(x, y, max_iter)
            x += step_x
        y += step_y

    return checksum

if __name__ == "__main__":
    s = mandelbrot(-2, -2, 2, 2, 500, 500, 1500)
    print(s)