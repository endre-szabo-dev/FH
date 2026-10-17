![Alt text](tools/logo.png "FH")

# FH

FH is designed to be embedded inside native applications (e.g. game engines),
where scripts are sandboxed, deterministic, and tightly integrated with C code.

## Getting Started

### Build

FH is a single C99 codebase with no external runtime dependencies. From the
repo root:

```text
$ make -j2
```

This produces the `fh` interpreter binary in the repo root. See `make check`
(valgrind), `make TARGETS=debug` and `make TARGETS=asan` for other build
modes, and `CLAUDE.md` for the full list of build/test commands.

### Run a script

```text
$ ./fh tests/mandelbrot.fh
```

Run the test suite with `./run_tests.sh` (executes every `tests/test_*.fh`
script through the real interpreter and checks its exit status).

### Embedding FH

FH's whole purpose is to be dropped into a host C/C++ application as a
scripting layer. The public embedding API is [`src/fh.h`](src/fh.h); the
typical pattern is:

```text
fh_init();                                        // once, process-wide
struct fh_program *prog = fh_new_program();
fh_add_c_func(prog, "my_host_func", my_host_func); // expose host functions to scripts
fh_compile_file(prog, "script.fh", true);          // compile a script into prog
struct fh_value ret;
fh_call_function(prog, "main", NULL, 0, &ret);      // call a script function
fh_free_program(prog);                              // tear down
```

`fh_add_c_func`/`fh_add_c_funcs` register C callbacks the script can call;
`fh_compile_file`/`fh_compile_input`/`fh_compile_pack` compile source (from a
file, an in-memory string, or a `.fhpack` archive) into a `fh_program`; and
`fh_call_function` invokes a named script function, passing/returning
`struct fh_value`s. See `src/main.c` for a complete, real usage of this
sequence (it's how the `fh` CLI itself runs scripts).

## Standard Library

FH's built-in functions (`string_*`, `math_*`, `io_*`, `os_*`, `json_*`,
plus core helpers like `len`, `append`, `has`, `type`, `assert`, `error`, and
GC controls) are documented with parameters, return values and examples in
[`docs/doc.mkd`](docs/doc.mkd).

## Docker Build

You can build and test `fh` using Docker (Alpine or Debian) without installing local dependencies.

```bash
# Build and test on Alpine (musl)
./build_docker.sh alpine build
./build_docker.sh alpine test

# Build and test on Debian (glibc)
./build_docker.sh debian build
./build_docker.sh debian test
```

## Features

- compilation to bytecode
- register-based VM.
- simple mark-and-sweep garbage collector
- full closures
- dynamic typing with `null`, `boolean`, `number`, `string`, `array`,
  `map`, `closure` `c_func` and `c user defined objects`
- simple standard library
- simple regex support
- simple tar support
- own packaging format
- hashing algorithms: bcrypt and md5
- uses fast and uniform random generator, mt19937

## Implementation Notes

- register-based virtual machine (fast dispatch with computed goto)
- bytecode compiler with type hints
- compact (~10k lines of C)
- no external runtime dependencies

## Error Reporting

FH provides detailed error messages with full stacktraces:

- **Error location**: File, line, and column number where the error occurred
- **Call stack**: Complete traceback showing the call chain from entry point to error
- **Function names**: Each frame shows which function was executing
- **Call sites**: Line numbers show where each function was called from

Example error output:
```
ERROR: file.fh:5:14: error: division by zero

Traceback (most recent call last):
  File "file.fh", line 33, in main
  File "file.fh", line 20, in process_data
  File "file.fh", line 16, in calculate_average
  File "file.fh", line 5, in divide
```

## Example Code

### Closures

```
fn make_counter(num) {
    return {
        "next" : fn() {
            num = num + 1;
        },

        "read" : fn() {
            return num;
        },
    };
}

fn main() {
    let c1 = make_counter(0);
    let c2 = make_counter(10);
    c1.next();
    c2.next();
    printf("%d, %d\n", c1.read(), c2.read());    # prints 1, 11

    c1.next();
    if (c1.read() == 2 && c2.read() == 11) {
        printf("ok!\n");
    } else {
        error("this should not happen");
    }
}
```

A closure returning a map of functions is how FH does objects: the locals it
captures are private state, each call makes an independent instance, and the
methods need no `self`. Section 1.12 of [`docs/doc.mkd`](docs/doc.mkd) covers
the pattern and how to give each object its own file.

### Mandelbrot Set

```
# check point c = (cx, cy) in the complex plane
fn calc_point(cx, cy, max_iter)
{
    # start at the critical point z = (x, y) = 0
    let x = 0;
    let y = 0;

    let i = 0;
    while (i < max_iter) {
        # calculate next iteration: z = z^2 + c
        let t = x*x - y*y + cx;
        y = 2*x*y + cy;
        x = t;

        # stop if |z| > 2
        if (x*x + y*y > 4)
            break;
        i = i + 1;
    }
    return i;
}

fn mandelbrot(x1, y1, x2, y2, size_x, size_y, max_iter)
{
    let step_x = (x2-x1) / (size_x-1);
    let step_y = (y2-y1) / (size_y-1);

    let y = y1;
    while (y <= y2) {
        let x = x1;
        while (x <= x2) {
            let n = calc_point(x, y, max_iter);
            if (n == max_iter)
                printf(".");         # in Mandelbrot set
            else
                printf("%d", n%10);  # outside
            x = x + step_x;
        }
        y = y + step_y;
        printf("\n");
    }
}

fn main()
{
  mandelbrot(-2, -2, 2, 2, 150, 50, 1500);
}
```

### Fibonacci

```
fn fib(n)
{
    if (n >= 2) {
        return fib (n - 1) + fib (n - 2);
    }
    else {
        return n;
    }
}

fn main() {
    printf("%f\n", fib(35));
}
```

## Editor Support

Editor integrations live under `tools/`:

- **Sublime Text** -- `tools/Sublime/FH` (syntax, completions, build system,
  symbol list; see its README for installation)
- **VS Code** -- `tools/VSCode/extensions/gwl.fh-0.1.0`
- **Vim** -- `tools/vim`

## License

Copyright (c) 2019-2026 Mureşan Vlad Mihail

Contact Info <muresanvladmihail@gmail.com

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. Shall you use this software
   in a product, an acknowledgment and the contact info(if there is any)
   of the author(s) must be placed in the product documentation.
2. This notice may not be removed or altered from any source distribution.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT.
IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER
LIABILITY, WHETHER IN CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Contributors

- Ricardo Massaro
- Bitpuffin
