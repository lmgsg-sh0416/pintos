#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define f (1 << 14)

#define CONV_F(x) (x * f)
#define ROUND_ZERO(x) (x / f)
#define ROUND_NEAR(x) (x >= 0 ? (x + f / 2) / f : (x - f / 2) / f)
#define ADD_F(x, y) (x + y)
#define SUB_F(x, y) (x - y)
#define ADD_I(x, n) (x + n * f)
#define SUB_I(x, n) (x - n * f)
#define MUL_F(x, y) ((int64_t)x * y / f)
#define MUL_I(x, n) (x * n)
#define DIV_F(x, y) ((int64_t)x * f / y)
#define DIV_I(x, n) (x / n)

#endif
