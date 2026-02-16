#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>

static int check_unicode_confusions(const char *command) {
	int confusions = 0;
	setlocale(LC_ALL, "");
	const unsigned char *p = (const unsigned char*)command;
	size_t i = 0;

	while(*p) {
        if (*p >= 0x80) {
            printf("argus: NON-ASCII char at position%zu: 0x%02X\n", i, *p);
            confusions++;
        }
        p++;
        i++;
    }
    if (confusions > 0) {
        printf("argus: %d suspicious/confusing Unicode character(s) detected\n", confusions);
    }
    return confusions;
}

static int ansi_esc_seq_and_invisibles_check(const char *command) {
    const unsigned char *p = (const unsigned char *)command;

    while (*p) {
        if (*p == 0x1B) {
            fprintf(stderr, "argus: BLOCKED - ANSI escape sequence detected at byte 0x1B\n");
            return 3;
        }

        // Check for string-escaped ANSI representations
        if (*p == '\\') {
            if (strncmp((const char *)p, "\\x1b", 4) == 0 || 
                strncmp((const char *)p, "\\x1B", 4) == 0 ||
                strncmp((const char *)p, "\\033", 4) == 0 ||
                strncmp((const char *)p, "\\e", 2) == 0) {
        
                fprintf(stderr, "argus: BLOCKED - Escaped ANSI sequence string detected\n");
                return 3;
            }
        }

        if ((*p == 'U' || *p == 'u') && *(p+1) == '+') {
            fprintf(stderr, "argus: BLOCKED - literal Unicode hex string detected\n");
            return 3;
        }

        if (*p == '\\' && (*(p+1) == 'u' || *(p+1) == 'U')) {
             fprintf(stderr, "argus: BLOCKED - explicit escape sequence detected\n");
             return 3;
        }

        if ((*p & 0xF0) == 0xE0){
            if (p[1] && p[2]) {
                uint32_t cp = ((p[0] & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
                if ((cp >= 0x200B && cp <= 0x200F) || (cp >= 0x202A && cp <= 0x202E) || (cp == 0xFEFF)) {
                    fprintf(stderr, "argus: BLOCKED - invisible or Bidi char U+%04X detected\n", cp);
                    return 3;
                }
                p += 2;
            }
        }
        p++;
    }
    return 0;
}

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

static int inspect_command(const char *command) {
    int rc = 0;
    if (strstr(command, "curl http://")) {
        fprintf(stderr, "argus: BLOCKED - insecure http transport\n");
        return 3;
    }
    
    if (strstr(command, "| bash") || strstr(command, "| sh")) {
        fprintf(stderr, "argus: WARNING - pipe-to-shell detected (\"%s\")\n", command);
        return 2;
    }

    int unicode_confusions = check_unicode_confusions(command);
    if (unicode_confusions) {
        fprintf(stderr, "argus: BLOCKED - potential homograph / confusable attack\n");
        return 3;
    }

    int ansi_detected = ansi_esc_seq_and_invisibles_check(command);
    if (ansi_detected) {
        return 3;
    }
    return rc;
}

static void shell_init_format(const char *shell) {
    if (!shell) shell = "bash";

    if (strcmp(shell, "bash") == 0) {
        puts(
            "trap 'cmd=$(history 1 | sed \"s/^ *[0-9]\\+ *//\"); "
            "argus check -- \"$cmd\" >/tmp/argus_out 2>&1; "
            "rc=$?; "
            "if [ $rc -eq 3 ]; then "
                "cat /tmp/argus_out >&2; kill -SIGINT $$; "
            "elif [ $rc -eq 2 ]; then "
                "cat /tmp/argus_out >&2; "
            "fi' DEBUG"
        );
    } else if (strcmp(shell, "zsh") == 0) {
        puts(
            "preexec() { "
            "argus check -- \"$1\" >/tmp/argus_out 2>&1; "
            "rc=$?; "
            "if [[ $rc -eq 3 ]]; then "
                "cat /tmp/argus_out >&2; kill -TERM $$; exit 3; "
            "elif [[ $rc -eq 2 ]]; then "
                "cat /tmp/argus_out >&2; "
            "fi; "
            "}"
        );
    } else if (strcmp(shell, "fish") == 0) {
        puts(
            "function argus_preexec --on-event fish_preexec; "
            "argus check -- \"$argv[1]\" >/tmp/argus_out 2>&1; "
            "set rc $status; "
            "if test $rc -eq 3; "
                "cat /tmp/argus_out >&2; "
            "end; "
            "end"
        );
    } else {
        fprintf(stderr, "Unsupported shell: %s\n", shell);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n" 
                " %s diff <string 1> <string 2>\n"
                " %s check -- \"<command>\"\n"
                " %s init --shell <bash|zsh|fish>\n", argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "diff") == 0 && argc >= 4) {
        return diff_checks(argv[2], argv[3]) ? 2 : 0;
    }

    if (strcmp(argv[1], "check") ==0 && argc >= 4 && strcmp(argv[2], "--") == 0) {
        return inspect_command(argv[3]);
    }

    if (strcmp(argv[1], "init") == 0) {
        const char *shell = NULL;
        for (int i =2; i < argc -1; ++i)
            if (strcmp(argv[i], "--shell") == 0) shell = argv[i + 1];
        shell_init_format(shell);
        return 0;
    }

    fprintf(stderr, "argus: unknown or incomplete command\n");
    return 1;
}
