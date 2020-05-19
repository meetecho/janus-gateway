if ENABLE_DOCS

doxygendir = $(htmldir)/janus-gateway-$(VERSION)

EXTRA_DIST = html

all: html-local

html-local:
	doxygen janus-doxygen.cfg
	cp doxy-boot.js html/
	mkdir -p html/css
	cp ../html/css/demo.css html/css/
	mkdir -p html/js
	cp ../html/favicon.ico html/
	cp ../html/meetecho-logo.png html/

install-data-local: html-local
	$(MKDIR_P) $(DESTDIR)$(doxygendir)
	cp -r html/ $(DESTDIR)$(doxygendir)

uninstall-local:
	rm -rf $(DESTDIR)$(doxygendir)

clean-local:
	rm -rf $(builddir)/html

endif
