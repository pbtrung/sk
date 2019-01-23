libsk_sources = files('''
'''.split())

libsk = static_library('sk',
                       libsk_sources,
                       include_directories : inc_dir)

subdir('vendor')

sk_sources = files('''
    main.c
'''.split())