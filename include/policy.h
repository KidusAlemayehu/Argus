#ifndef ARGUS_POLICY_H
#define ARGUS_POLICY_H

#include <stddef.h>

typedef enum {
    RULE_IGNORE =0,
    RULE_WARN = 1,
    RULE_BLOCK = 2
} RuleAction;

typedef struct {
    RuleAction insecure_http;
    RuleAction pipe_to_shell;
    RuleAction unicode_confusable;
    RuleAction ansi_sequence;

    char **allowlist;
    size_t allowlist_count;

    int fail_closed;
} ArgusPolicy;

void argus_policy_init(ArgusPolicy *p);
void argus_policy_free(ArgusPolicy *p);
int argus_policy_match_llowlist(const ArgusPolicy *p, const char *command);

#endif
