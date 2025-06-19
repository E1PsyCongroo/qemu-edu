#ifndef _TEST_H_
#define _TEST_H_

void test_start_musl();

int run_test(char *const argv[]);

void test_musl_basic();
void test_musl_busybox();
void test_musl_libc();
void test_musl_lua();

#endif
