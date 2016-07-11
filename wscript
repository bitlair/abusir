top = '.'
out = 'build'

def options(opt):
    opt.load('compiler_c')

def configure(conf):
    conf.load('compiler_c')
    conf.env.CFLAGS = ['-O0', '-std=gnu11', '-pedantic', '-g', '-Wall', '-Wextra', '-Winit-self',
                       '-Wformat-security', '-Wshadow', '-Wpointer-arith', '-Wcast-align', '-Wwrite-strings',
                       '-Werror-implicit-function-declaration', '-Wstrict-prototypes',
                       '-fPIC', '-pie', '-fstack-protector', '-DFORTIFY_SOURCE=2']
    conf.env.LDFLAGS = ['-fPIC', '-pie', '-z', 'relro', '-z', 'now', '-fstack-protector']

def build(bld):
    bld.program(source='main.c', target='abusir', use='mainobjects')
    #bld.stlib(source='a.c', target='mystlib')
    #bld.shlib(source='b.c', target='myshlib', use='mainobjects')
    #bld.objects(source='blub.c', target='mainobjects')
