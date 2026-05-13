// testprog.c — small test program for probdisasm evaluation.
// Mix of patterns to exercise hint extractors: control-flow convergence
// (multiple branches sharing a target via if/else and loops), control-flow
// crossing (branches landing past other branches), and register def-use
// (locals threaded through arithmetic).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int bubble_sort(int *a, int n) {
    int swaps = 0;
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - 1 - i; j++) {
            if (a[j] > a[j + 1]) {
                int tmp = a[j];
                a[j] = a[j + 1];
                a[j + 1] = tmp;
                swaps++;
            }
        }
    }
    return swaps;
}

static int binary_search(const int *a, int n, int needle) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (a[mid] == needle) return mid;
        if (a[mid] < needle) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}

static unsigned long factorial(unsigned long n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

static int fib(int n) {
    if (n < 2) return n;
    int a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int c = a + b;
        a = b;
        b = c;
    }
    return b;
}

static void reverse_str(char *s) {
    size_t n = strlen(s);
    for (size_t i = 0; i < n / 2; i++) {
        char tmp = s[i];
        s[i] = s[n - 1 - i];
        s[n - 1 - i] = tmp;
    }
}

static int sum_evens(const int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if ((a[i] & 1) == 0) s += a[i];
    }
    return s;
}

static int max_of(const int *a, int n) {
    int m = a[0];
    for (int i = 1; i < n; i++) {
        if (a[i] > m) m = a[i];
    }
    return m;
}

int main(int argc, char **argv) {
    int data[] = {17, 3, 42, 8, 91, 5, 27, 14, 60, 33};
    int n = sizeof(data) / sizeof(data[0]);

    int swaps = bubble_sort(data, n);
    printf("sorted with %d swaps\n", swaps);

    int idx = binary_search(data, n, 33);
    printf("33 is at index %d\n", idx);

    printf("10! = %lu\n", factorial(10));
    printf("fib(20) = %d\n", fib(20));
    printf("sum of evens = %d\n", sum_evens(data, n));
    printf("max = %d\n", max_of(data, n));

    char buf[] = "reversible";
    reverse_str(buf);
    printf("reversed = %s\n", buf);

    if (argc > 1) {
        printf("got arg: %s\n", argv[1]);
    }
    return 0;
}
