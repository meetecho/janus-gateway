if ENABLE_DOCS

doxygendir = $(htmldir)/janus-gateway-$(VERSION)

EXTRA_DIST = html

all: html-local

html-local:
	cd $(srcdir) && doxygen janus-doxygen.cfg
	mkdir -p html
	cp $(srcdir)/doxy-boot.js html/
	cp $(srcdir)/../html/jquery.min.js html/jquery.js
	cp $(srcdir)/dynsections.js html/
	mkdir -p html/css
	cp $(srcdir)/../html/css/cerulean/bootstrap.css html/css/
	cp $(srcdir)/../html/css/demo.css html/css/
	mkdir -p html/js
	cp $(srcdir)/../html/js/bootstrap.min.js html/js/
	cp $(srcdir)/../html/favicon.ico html/
	cp $(srcdir)/../html/meetecho-logo.png html/

install-data-local: html-local
	$(MKDIR_P) $(DESTDIR)$(doxygendir)
	cp -r html/ $(DESTDIR)$(doxygendir)

uninstall-local:
	rm -rf $(DESTDIR)$(doxygendir)

clean-local:
	rm -rf $(builddir)/html

endif
