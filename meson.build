project('sk', 'c', 
		version : '0.0.9999',
        license : 'BSD-3-Clause',
        default_options : 'c_std=c11')

cc = meson.get_compiler('c')

c_args = '''
    -Wall
    -Wextra 
    -Wpedantic
    -Wformat=2 
    -Wno-unused-parameter 
    -Wshadow
    -Wno-parentheses
    -Wwrite-strings 
    -Wstrict-prototypes
    -Wold-style-definition
    -Wnested-externs
    -Wmissing-include-dirs 
    -Wno-type-limits
    -DSQLITE_ENABLE_COLUMN_METADATA=1
    -DSQLITE_ENABLE_UNLOCK_NOTIFY
    -DSQLITE_ENABLE_DBSTAT_VTAB=1
    -DSQLITE_ENABLE_FTS3_TOKENIZER=1
    -DSQLITE_SECURE_DELETE
    -DSQLITE_MAX_VARIABLE_NUMBER=250000
    -DSQLITE_MAX_EXPR_DEPTH=10000
    -DSQLITE_ENABLE_FTS3
    -DSQLITE_ENABLE_FTS4
    -DSQLITE_ENABLE_FTS5
    -DSQLITE_ENABLE_JSON1
    -DSQLITE_ENABLE_RTREE
    -DSQLITE_ENABLE_DESERIALIZE
'''.split()

foreach arg: c_args
    if cc.has_argument(arg)
        add_project_arguments(arg, language : 'c')
    endif
endforeach

libcurl = dependency('libcurl', version : '>= 7.63.0')
libsodium = dependency('libsodium', version : '>= 1.0.17')
threads = dependency('threads')
dl = cc.find_library('dl', required: true)
m = cc.find_library('m', required: true)

inc_dir = include_directories(['src/vendor'])

subdir('src')
subdir('tests')

dependencies = [libcurl, libsodium, threads, dl, m]

executable('sk', sk_sources,
		   link_with : [libsk, libvendor],
		   dependencies : dependencies,
           install : false,
		   include_directories : inc_dir)
