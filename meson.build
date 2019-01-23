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
