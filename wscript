top = '.'
out = 'build'

def options(opt):
    opt.load('compiler_c')

def configure(conf):
    conf.load('compiler_c')
    conf.env.CFLAGS = ['-O1', '-std=gnu11', '-pedantic', '-g', '-Wall', '-Wextra', '-Winit-self',
                       '-Wformat-security', '-Wshadow', '-Wpointer-arith', '-Wcast-align', '-Wwrite-strings',
                       '-Werror-implicit-function-declaration', '-Wstrict-prototypes',
                       '-fPIC', '-pie', '-fstack-protector', '-D_FORTIFY_SOURCE=2']
    conf.env.LDFLAGS = ['-fPIC', '-pie', '-z', 'relro', '-z', 'now', '-fstack-protector']
    conf.check(msg='Checking compiler flags', features='c cprogram')

    conf.check_cfg(package='libconfig', uselib_store='libconfig',
                args=['--cflags', '--libs'])
    conf.check(header_name='arpa/inet.h', features='c cprogram')
    conf.check(header_name='errno.h', features='c cprogram')
    conf.check(header_name='libconfig.h', features='c cprogram')
    conf.check(header_name='limits.h', features='c cprogram')
    conf.check(header_name='netinet/icmp6.h', features='c cprogram')
    conf.check(header_name='netinet/if_ether.h', features='c cprogram')
    conf.check(header_name='netinet/in.h', features='c cprogram')
    conf.check(header_name='netinet/ip6.h', features='c cprogram')
    conf.check(header_name='stdio.h', features='c cprogram')
    conf.check(header_name='stdlib.h', features='c cprogram')
    conf.check(header_name='sys/socket.h', features='c cprogram')


def build(bld):
    bld.program(source='main.c', target='abusir', use='mainobjects libconfig')
    bld.objects(source='hexdump.c sock.c', target='mainobjects')
