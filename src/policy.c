#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>

#include "../include/policy.h"

static void trim_space(char *s) {
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

static void add_allowlist(ArgusPolicy *p, const char *entry) {
    p->allowlist = realloc(p->allowlist, sizeof(char*) * (p->allowlist_count + 1));
    p->allowlist[p->allowlist_count] = strdup(entry);
    p->allowlist_count++;
}


static void parse_policy_line(ArgusPolicy *p, char *line) {
    trim_space(line);
    if (line[0] == '#' || strlen(line) == 0) return;

    if (strstr(line, "insecure_http: warn")) p->insecure_http = RULE_WARN;
    else if (strstr(line, "insecure_http: ignore")) p->insecure_http = RULE_IGNORE;
    else if (strstr(line, "insecure_http: block")) p->insecure_http = RULE_BLOCK;

    else if (strstr(line, "pipe_to_shell: warn")) p->pipe_to_shell = RULE_WARN;
    else if (strstr(line, "pipe_to_shell: ignore")) p->pipe_to_shell = RULE_IGNORE;
    else if (strstr(line, "pipe_to_shell: block")) p->pipe_to_shell = RULE_BLOCK;

    else if (strstr(line, "unicode_confusable: warn")) p->unicode_confusable = RULE_WARN;
    else if (strstr(line, "unicode_confusable: ignore")) p->unicode_confusable = RULE_IGNORE;
    else if (strstr(line, "unicode_confusable: block")) p->unicode_confusable = RULE_BLOCK;

    else if (strstr(line, "ansi_sequence: warn")) p->ansi_sequence = RULE_WARN;
    else if (strstr(line, "ansi_sequence: ignore")) p->ansi_sequence = RULE_IGNORE;
    else if (strstr(line, "ansi_sequence: block")) p->ansi_sequence = RULE_BLOCK;

    else if (strstr(line, "fail_mode: closed")) p->fail_closed = 1;

    else if (strstr(line, "- ")) { // allowlist entry
        const char *url = strchr(line, ' ');
        if (url) add_allowlist(p, url + 1);
    }
}

static void load_policy_file(ArgusPolicy *p, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        parse_policy_line(p, line);
    }
    fclose(f);
}

void argus_policy_init(ArgusPolicy *p) {
    load_default_policy(p);

    const char *home = getenv("HOME");
    char path[512];

    if (access(".argus/policy.yaml", R_OK) == 0) {
        load_policy_file(p, ".argus/policy.yaml");
        return;
    }

    if (home) {
        snprintf(path, sizeof(path), "%s/.config/argus/policy.yaml", home);
        if (access(path, R_OK) == 0) {
            load_policy_file(p, path);
            return;
        }
    }
}

int argus_policy_match_allowlist(const ArgusPolicy *p, const char *command) {
    for (size_t i = 0; i < p->allowlist_count; i++) {
        if (strstr(command, p->allowlist[i])) return 1;
    }
    return 0;
}

void argus_policy_free(ArgusPolicy *p) {
    for (size_t i = 0; i < p->allowlist_count; i++) {
        free(p->allowlist[i]);
    }
    free(p->allowlist);
}
