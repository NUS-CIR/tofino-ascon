#pragma once
// some C macros to implement loop expansion
#define loop1(f) f(0)
#define loop2(f) loop1(f) f(1)
#define loop3(f) loop2(f) f(2)
#define loop4(f) loop3(f) f(3)
#define loop5(f) loop4(f) f(4)
#define loop6(f) loop5(f) f(5)
#define loop7(f) loop6(f) f(6)
#define loop8(f) loop7(f) f(7)
#define loop9(f) loop8(f) f(8)
#define xloop(n,f) loop##n(f)
#define __LOOP(n,f) xloop(n,f) 
// two-level indirection required for macro name expansion.
// __LOOP(4,f) expands to f(0) f(1) f(2) f(3)
