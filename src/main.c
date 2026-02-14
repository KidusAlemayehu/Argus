#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int diff_checks(const char *a, const char *b){
int diff = 0 ;
size_t i= 0;

while (a[i] && b[i]) {
    if (a[i] != b[i]) {
        printf("positon %zu: '%c' (0x%02X) vs '%c' (0x%02X)\n", i, a[i], (unsigned char)a[i], b[i], (unsigned char)b[i]);
        diff++;
    }
    i++;
}
if (a[i] || b[i]) {
    printf("length differs: a=%zu b=%zu\n", strlen(a), strlen(b));
    diff++;
}
return diff;
}

int main(int argc, char *argv[]) {
    printf("Hello From Argus");
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <string !> <string 2>\n", argv[0]);
        return 1;
    }

    printf("Argus diff - first watch\n");
    int diffs = diff_checks(argv[1], argv[2]);
    if (diffs == 0) {
        printf("Good to go");
        return 0;
    } else {
        printf("%d diffrence(s) found.\n", diffs);
        return 2;
    }
}
