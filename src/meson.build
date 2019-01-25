libsk_sources = files('''
	crypto.c
	utils.c
    db.c
'''.split())

libsk = static_library('sk',
                       libsk_sources,
                       include_directories : inc_dir)

subdir('vendor')

sk_sources = files('''
    main.c
'''.split())