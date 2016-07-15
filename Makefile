.PHONY: all clean distclean configure splint scanbuild coverity
all:
	@./waf build

clean:
	@./waf clean

distclean:
	@./waf distclean

configure:
	@./waf configure

splint:
	@for i in *.c;do splint $$i;done

scanbuild:
	@scan-build ./waf configure clean build

coverity:
	@if [ -d cov-int ]; then rm -rf cov-int;fi
	@mkdir cov-int
	@cov-build --dir=cov-int ./waf configure clean build
	@tar cvzf coverity_abusir.tgz cov-int
	@rm -rf cov-int
