libvendor_sources = files('''
    lz4/lz4.c
    argparse/argparse.c
    sqlite3/sqlite3.c
    argon2/core.c
    argon2/thread.c
    argon2/opt.c
    argon2/encoding.c
    argon2/blake2b.c
    argon2/argon2.c
    skein3fish/skein.c
    skein3fish/skeinApi.c
    skein3fish/skeinBlockNo3F.c
    skein3fish/threefish1024Block.c
    skein3fish/threefish256Block.c
    skein3fish/threefish512Block.c
    skein3fish/threefishApi.c
'''.split())

libvendor = static_library('vendor',
                           libvendor_sources,
                           include_directories : inc_dir)