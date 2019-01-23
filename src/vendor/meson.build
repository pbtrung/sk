libvendor_sources = files('''
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