#ifndef _CALC_MATH_H_
#define _CALC_MATH_H_

#include <time.h>
#include <stdlib.h>

#ifndef KEY_LENGTH 
#define KEY_LENGTH 64
#endif

#ifndef KEY_SIZE
#define KEY_SIZE KEY_LENGTH
#endif

#define CALC_LENGTH (KEY_LENGTH / 2)

#define LOOP_LENGTH 7

#define CALC_MILLER_RABBIN_TEST 64

typedef unsigned int uint32;
typedef unsigned char uint8;
typedef unsigned long long uint64;

typedef struct {
  uint32 x[KEY_LENGTH + 3];
  uint32 len;
}calc_bigint;

void calc_set_randseed() {
  static int first = 1;
  if(first) 
    srand(time(NULL));
  first = 0;
}

void calc_output_as_list(calc_bigint x) {
  printf("[");
  for(int i = 0; i < x.len - 1; ++i)
    printf("%u, ", x.x[i]);
  printf("%u]\n", x.x[x.len - 1]);
}

void calc_check_len(calc_bigint *x) {
  while(x->len != 1 && !x->x[x->len - 1])
    --x->len;
}

int calc_zero(calc_bigint x) {
  return x.len == 1 && !x.x[0];
}

int calc_one(calc_bigint x) {
  return x.len == 1 && x.x[0] == 1;
}

void calc_to_bigint(uint8 *x, calc_bigint *res) {
  memset(res, 0, sizeof(calc_bigint));
  for(int i = 0; i < KEY_LENGTH; i += 2)
    res->x[i >> 1] = x[i + 1] << 8 | x[i];
  res->len = CALC_LENGTH;
  calc_check_len(res);
}

void calc_to_string(calc_bigint x, uint8 *res) {
  memset(res, 0, KEY_SIZE);
  for(int i = 0; i < KEY_LENGTH; i += 2) {
    res[i] = x.x[i >> 1] & 0xFF;
    res[i + 1] = x.x[i >> 1] >> 8;
  }
}

void calc_set(calc_bigint *x, uint32 y) {
  memset(x, 0, sizeof(calc_bigint));
  x->x[0] = y;
  x->len = 1;
}

int calc_compare(calc_bigint x, calc_bigint y) {
  if(x.len != y.len)
    return x.len < y.len ? 1 : -1;
  for(int i = x.len - 1; i >= 0; --i)
    if(x.x[i] != y.x[i])
      return x.x[i] < y.x[i] ? 1 : -1;
  return 0;
}

int calc_less(calc_bigint x, calc_bigint y) {
  return calc_compare(x, y) == 1;
}

int calc_equal(calc_bigint x, calc_bigint y) {
  return calc_compare(x, y) == 0;
}

int calc_greater(calc_bigint x, calc_bigint y) {
  return calc_compare(x, y) == -1;
}

void calc_add(calc_bigint x, calc_bigint y, calc_bigint *res) {
  calc_set(res, 0);
  res->len = (x.len > y.len ? x.len : y.len) + 1;
  for(int i = 0; i < res->len; ++i) {
    res->x[i] = x.x[i] + y.x[i];
    res->x[i + 1] += res->x[i] >> 16;
    res->x[i] &= 0xFFFF;
  }
  calc_check_len(res);
}

void calc_add1(calc_bigint *x) {
  ++x->x[0];
  for(int i = 0; x->x[i] > 0xFFFF; ++i) {
    x->x[i] >> 16;
    ++x->x[i + 1];
  }
  ++x->len;
  calc_check_len(x);
}

// REQUIRE: x >= y
void calc_sub(calc_bigint x, calc_bigint y, calc_bigint *res) {
  calc_set(res, 0);
  res->len = x.len;
  for(int i = 0; i < x.len; ++i) {
    res->x[i] = 0x10000 + x.x[i] - y.x[i];
    x.x[i + 1] -= !(res->x[i] >> 16);
    res->x[i] &= 0xFFFF;
  }
  calc_check_len(res);
}    

void calc_multiply(calc_bigint x, calc_bigint y, calc_bigint *res) {
  uint64 t;
  calc_set(res, 0);
  for(int i = 0; i < x.len; ++i)
    for(int j = 0; j < y.len; ++j) {
      t = 1LL * x.x[i] * y.x[j] + res->x[i + j];
      res->x[i + j] = t & 0xFFFF;
      res->x[i + j + 1] += t >> 16;
    }
  res->len = x.len + y.len;
  calc_check_len(res);
}

void calc_div2(calc_bigint *x) {
  uint32 re = 0;
  for(int i = x->len; i >= 0; --i) {
    re = (re << 16) | x->x[i];
    x->x[i] = re >> 1;
    re &= 1;
  }
  calc_check_len(x);
}

void calc_multiply2(calc_bigint *x) {
  uint32 re = 0;
  for(int i = 0; i <= x->len; ++i) {
    re = re | (x->x[i] << 1);
    x->x[i] = re & 0xFFFF;
    re >>= 16;
  }
  x->x[x->len++] = re;
  calc_check_len(x);
}

void calc_mod(calc_bigint x, calc_bigint y, calc_bigint *res) {
  int off = x.len - y.len + 1;
  memcpy(res, &x, sizeof(calc_bigint));
  for(int i = y.len - 1; i >= 0; --i) {
    y.x[i + off] = y.x[i];
    y.x[i] = 0;
  }
  y.len += off;
  calc_div2(&y);
  for(int i = off - 1; i >= 0; --i) 
    for(int j = 15; j >= 0; --j) {
      if(calc_less(y, *res)) 
	calc_sub(*res, y, res);
      calc_div2(&y);
    }
}

void calc_multiply_mod(calc_bigint x, calc_bigint y, calc_bigint mod, calc_bigint *res) {
  calc_multiply(x, y, res);
  calc_mod(*res, mod, res);
}

void calc_power(calc_bigint x, calc_bigint y, calc_bigint mod, calc_bigint *res) {
  calc_set(res, 1);
  while(!calc_zero(y)) {
    if(y.x[0] & 1)
      calc_multiply_mod(*res, x, mod, res);
    calc_multiply_mod(x, x, mod, &x);
    calc_div2(&y);
  }
}
    
void calc_power_uint8(uint8 *a, uint8 *b, uint8 *p, uint8 *res) {
  calc_bigint x, y, z;
  calc_to_bigint(a, &x);
  calc_to_bigint(b, &y);
  calc_to_bigint(p, &z);
  calc_power(x, y, z, &x);
  calc_to_string(x, res);
}
  
void calc_generate_rand(calc_bigint *res, int len) {
  calc_set_randseed();
  calc_set(res, 0);
  res->len = len;
  for(int i = 0; i < len; ++i)
    res->x[i] = random() & 0xFFFF;
  calc_check_len(res);
}

// generated res < x
void calc_generate_rand_less(calc_bigint x, calc_bigint *res) {
  calc_set_randseed();
  calc_set(res, 0);
  do {
    for(int i = 0; i < x.len - 1; ++i)
      res->x[i] = random() & 0xFFFF;
    res->x[x.len - 1] = random() % (x.x[x.len - 1] + 1);
    res->len = x.len;
    calc_check_len(res);
  }while(!calc_less(*res, x) || calc_zero(*res));
}

// generated res < x && res > 2^{16x}
void calc_generate_rand_less_len(calc_bigint x, uint32 len, calc_bigint *res) {
  do {
    calc_generate_rand_less(x, res);
  }while(res->len <= len);
}

void calc_generate_rand_less_len_uint8(uint8 *x, uint32 len, uint8 *res) {
  calc_bigint a, b;
  calc_to_bigint(x, &b);
  calc_generate_rand_less_len(b, len, &a);
  calc_to_string(a, res);
}

int calc_miller_rabbin_test(calc_bigint x) {
  // @x = y * 2^t
  int t = 0;
  calc_bigint y, a, b;
  memcpy(&y, &x, sizeof(calc_bigint));
  --y.x[0];
  while(~y.x[0] & 1) {
    ++t;
    calc_div2(&y);
  }
  for(int i = 0; i < CALC_MILLER_RABBIN_TEST; ++i) {
    calc_generate_rand_less(x, &a);
    calc_power(a, y, x, &a);
    for(int j = 0; j < t; ++j) {
      memcpy(&b, &a, sizeof(calc_bigint));
      calc_multiply_mod(a, a, x, &a);
      if(calc_one(a)) {
	if(calc_one(b))
	  continue;
	calc_add1(&b);
	if(!calc_equal(b, x))
	  return 0;
      }
    }
    if(!calc_one(a))
      return 0;
  }
  return 1;
}

void calc_generate_randprime(calc_bigint *res) {
  do {
    calc_generate_rand(res, LOOP_LENGTH);
    res->x[0] |= 1;
    if(res->len == CALC_LENGTH) {
      res->x[CALC_LENGTH - 1] &= 0x7FFF;
      calc_check_len(res);
    }
    if(calc_zero(*res))
      continue;
    if(calc_miller_rabbin_test(*res))
      break;
  }while(1);
  printf("1\n");
  calc_bigint t;
  do {
    printf("0\n");
    calc_generate_rand(&t, CALC_LENGTH - LOOP_LENGTH);
    calc_multiply(*res, t, &t);
    calc_add1(&t);
  }while(!calc_miller_rabbin_test(t));
  memcpy(res, &t, sizeof(calc_bigint));
}

void calc_generate_g(calc_bigint p, calc_bigint *g) {
  calc_bigint a, b;
  memcpy(&a, &p, sizeof(calc_bigint));
  calc_div2(&a);
  for(int i = 2; ; ++i) {
    calc_set(&b, i);
    calc_power(b, a, p, &b);
    if(!calc_one(b)) {
      calc_set(g, i);
      break;
    }
  }
  do {
    calc_generate_rand_less(p, &b);
    b.x[0] |= 1;
  }while(!calc_equal(a, b)); // b != a;
  calc_power(*g, b, p, g);
}

void calc_generate_p_g_a(uint8 *p, uint8 *g, uint8 *a) {
  calc_bigint bp, bg, ba;
  calc_generate_randprime(&bp);
  calc_generate_g(bp, &bg);
  calc_generate_rand_less_len(bp, 5, &ba);
  calc_to_string(bp, p);
  calc_to_string(bg, g);
  calc_to_string(ba, a);
}

#endif
