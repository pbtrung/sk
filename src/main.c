#define ZPL_IMPLEMENTATION
#include "zpl.h"

int main(int argc, char **argv) {

    zpl_opts opts = {0};
    zpl_opts_init(&opts, zpl_heap(), argv[0]);

    zpl_opts_add(&opts, "sf", "salt-file", "input salt file name.", ZPL_OPTS_STRING);
    zpl_opts_positional_add(&opts, "salt-file");

    b32 rc = zpl_opts_compile(&opts, argc, argv);
    b32 strip_comments = true;
    char *salt_file = NULL;

    if (rc && zpl_opts_positionals_filled(&opts)) {
        salt_file = zpl_opts_string(&opts, "salt-file", NULL);
        if (salt_file == NULL)
            goto err;

        printf("Salt file: %s\n", salt_file);
    } else {
    err:
        zpl_opts_print_errors(&opts);
        zpl_opts_print_help(&opts);
        return EXIT_FAILURE;
    }
    
    zpl_file_contents fc = zpl_file_read_contents(zpl_heap(), true, salt_file);
    printf("File size: %lld bytes\n", fc.size);

    zpl_file_free_contents(&fc);
    zpl_opts_free(&opts);
    
    return EXIT_SUCCESS;
}