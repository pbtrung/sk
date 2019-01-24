#include <sodium.h>

#define ZPL_IMPLEMENTATION
#include "zpl.h"

#include "argon2/argon2.h"

#define PWD_LEN 256
#define SALT_LEN 32
#define PWD_FILE_SIZE (PWD_LEN + SALT_LEN)
#define HASH_LEN 128

char *sk_read_line(void) {
    char *line = NULL;
    size_t buf_size = 0;
    ssize_t rc = getline(&line, &buf_size, stdin);
    if (rc < 0) {
        printf("Error: Cannot get input from console.\n");
        exit(EXIT_FAILURE);
    }
    return line;
}

#define SK_TOK_BUFSIZE 64
#define SK_TOK_DELIM " \t\r\n\a"
char **sk_split_line(char *line) {
    int buf_size = SK_TOK_BUFSIZE, position = 0;

    char **tokens = malloc(buf_size * sizeof(char *));
    if (!tokens) {
        printf("Error: Cannot allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    char *token;

    token = strtok(line, SK_TOK_DELIM);
    while (token != NULL) {
        tokens[position] = token;
        position++;

        if (position >= buf_size) {
            buf_size += SK_TOK_BUFSIZE;
            tokens = realloc(tokens, buf_size * sizeof(char *));
            if (!tokens) {
                printf("Error: Cannot allocate memory.\n");
                exit(EXIT_FAILURE);
            }
        }

        token = strtok(NULL, SK_TOK_DELIM);
    }
    tokens[position] = NULL;
    return tokens;
}

char *cmds[] = {"sw", "show", "h", "help", "x", "exit", "q", "quit"};

int sk_num_cmds() { return sizeof(cmds) / sizeof(char *); }

int sk_cmd_exit(char **args) { return 0; }

int sk_cmd_help(char **args) { 
    printf("Commands:");
    printf("\n");
    printf("%4s%-20s%s", "", "h, help", "show this help");
    printf("\n");
    printf("%4s%-20s%s", "", "sw, show", "show entries");
    printf("\n");
    printf("%4s%-20s%s", "", "sh, search", "search entries");
    printf("\n");
    printf("%4s%-20s%s", "", "x, q, exit, quit", "exit/quit");
    printf("\n");
    printf("%4s%-20s%s", "", "a, add", "add entry");
    printf("\n");
    return 1;
}

int sk_cmd_show(char **args) { return 0; }

int (*sk_cmd_func[])(char **) = {&sk_cmd_show, &sk_cmd_show, &sk_cmd_help,
                                 &sk_cmd_help, &sk_cmd_exit, &sk_cmd_exit,
                                 &sk_cmd_exit, &sk_cmd_exit};

int sk_execute(char **args) {
    if (args[0] == NULL) {
        return 1;
    }

    for (int i = 0; i < sk_num_cmds(); i++) {
        if (strcmp(args[0], cmds[i]) == 0) {
            return (*sk_cmd_func[i])(args);
        }
    }

    return 1;
}

int main(int argc, char **argv) {

    if (sodium_init() < 0) {
        printf(
            "Error: libsodium cannot be initialized. It is not safe to use.\n");
        return EXIT_FAILURE;
    }

    zpl_opts opts = {0};
    zpl_opts_init(&opts, zpl_heap(), argv[0]);

    zpl_opts_add(&opts, "p", "pwd-file",
                 "input local path to password file (REQUIRED).",
                 ZPL_OPTS_STRING);
    zpl_opts_positional_add(&opts, "pwd-file");
    zpl_opts_add(&opts, "l", "local-path", "input local path to your database.",
                 ZPL_OPTS_STRING);
    zpl_opts_add(&opts, "u", "url", "input remote path (URL) to your database.",
                 ZPL_OPTS_STRING);

    b32 rc = zpl_opts_compile(&opts, argc, argv);
    char *pwd_file_path = NULL;

    if (rc == true && zpl_opts_positionals_filled(&opts) &&
        (zpl_opts_has_arg(&opts, "local-path") ||
         zpl_opts_has_arg(&opts, "url")) &&
        !(zpl_opts_has_arg(&opts, "local-path") &&
          zpl_opts_has_arg(&opts, "url"))) {
        pwd_file_path = zpl_opts_string(&opts, "pwd-file", NULL);
        if (pwd_file_path == NULL)
            goto err;
    } else {
    err:
        zpl_opts_print_errors(&opts);
        zpl_opts_print_help(&opts);
        return EXIT_FAILURE;
    }

    zpl_file pwd_file = {0};
    zplFileError file_err = zpl_file_open(&pwd_file, pwd_file_path);
    if (file_err != ZPL_FILE_ERROR_NONE) {
        printf("Error: Cannot open password file.\n");
        return EXIT_FAILURE;
    }
    i64 file_size = zpl_file_size(&pwd_file);
    if (file_size != PWD_FILE_SIZE) {
        printf("Error: File size must be 288 bytes\n");
        return EXIT_FAILURE;
    }
    unsigned char *fc = sodium_malloc(PWD_FILE_SIZE);
    if (fc == NULL) {
        printf("Error: Cannot allocate memory.\n");
        return EXIT_FAILURE;
    }
    rc = zpl_file_read(&pwd_file, fc, PWD_FILE_SIZE);
    if (rc == false) {
        printf("Error: Cannot read file.\n");
        return EXIT_FAILURE;
    }
    zpl_file_close(&pwd_file);
    
    unsigned char *pwd = sodium_malloc(PWD_LEN);
    if (pwd == NULL) {
        printf("Error: Cannot allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *salt = sodium_malloc(SALT_LEN);
    if (salt == NULL) {
        printf("Error: Cannot allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *hash = sodium_malloc(HASH_LEN);
    if (hash == NULL) {
        printf("Error: Cannot allocate memory.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(pwd, fc, PWD_LEN);
    memcpy(salt, &fc[PWD_LEN], SALT_LEN);
    sodium_memzero(fc, PWD_FILE_SIZE);
    sodium_free(fc);
    
    uint32_t t = 8;
    uint32_t m = (1 << 18);
    uint32_t p = 1;
    
    printf("Hashing password ");
    fflush(stdout);
    f64 time = zpl_time_now();
    int ag2_rc = argon2id_hash_raw(t, m, p, pwd, PWD_LEN, salt, SALT_LEN, hash, HASH_LEN);
    f64 delta = zpl_time_now() - time;
    printf("needs %f second(s).\n\n", delta);
    if (ag2_rc != ARGON2_OK) {
        printf("Error: Cannot derive password using Argon2.\n");
        exit(EXIT_FAILURE);
    }
    sodium_memzero(pwd, PWD_LEN);
    sodium_free(pwd);
    sodium_memzero(salt, SALT_LEN);
    sodium_free(salt);

    char *line = NULL;
    char **args = NULL;
    int status = 1;
    
    printf("Press h for help.\n");
    do {
        printf("sk >> ");
        line = sk_read_line();
        args = sk_split_line(line);
        status = sk_execute(args);

        free(line);
        free(args);
    } while (status);
    
    zpl_opts_free(&opts);

    return EXIT_SUCCESS;
}