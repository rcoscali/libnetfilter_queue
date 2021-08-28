if HAVE_DOXYGEN

doc_srcs = $(shell find $(top_srcdir)/src -name '*.c')

doxyfile.stamp: $(doc_srcs) Makefile.am
	rm -rf html man

# Test for running under make distcheck.
# If so, sibling src directory will be empty:
# move it out of the way and symlink the real one while we run doxygen.
	[ -f ../src/Makefile.in ] || \
{ set -x; cd ..; mv src src.distcheck; ln -s $(top_srcdir)/src; }

	cd ..; doxygen doxygen.cfg >/dev/null

	[ ! -d ../src.distcheck ] || \
{ set -x; cd ..; rm src; mv src.distcheck src; }

	$(abs_top_srcdir)/doxygen/build_man.sh

	touch doxyfile.stamp

CLEANFILES = doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf $(top_srcdir)/doxygen/man $(top_srcdir)/doxygen/html
install-data-local:
	mkdir -p $(DESTDIR)$(mandir)/man3
	cp --no-dereference --preserve=links,mode,timestamps man/man3/*.3\
	  $(DESTDIR)$(mandir)/man3/

# make distcheck needs uninstall-local
uninstall-local:
	rm -r $(DESTDIR)$(mandir) man html doxyfile.stamp
endif

EXTRA_DIST = build_man.sh
