all:
	@./waf build

clean:
	@./waf clean

configure:
	@./waf configure

splint:
	@for i in *.c;do splint $$i;done

scanbuild:
	CC=clang scan-build ./waf configure clean build

