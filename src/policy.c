#include "include/policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void trim_space(char *S) {
    char *last;
    while (isspace((unsigned char)*s)) s++;
    if (*s == 0) return;
    last = s +strlen(s) - 1;
    while (last > s && isspace((unsigned char)*last)) last--;
    *(last + 1) = 0;
}

static void load_default_policy(ArgusPolicy *p) {
    p->insecure_http = RULE_BLOCK;
    p->pipe_to_shell = RULE_WARN;
    p->unicode_confusable = RULE_BLOCK;
    p->ansi_sequence = RULE_BLOCK;
    p->allowlist = NULL;
    p->allowlist_count = 0;
    p->fail_closed = 0;
}
