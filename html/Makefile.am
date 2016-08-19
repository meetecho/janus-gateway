demodir = $(datadir)/janus/demos

html-local:
	true

install-data-local: html-local
	$(MKDIR_P) $(DESTDIR)$(demodir)
	cp -r $(srcdir)/* $(DESTDIR)$(demodir)
	rm $(DESTDIR)$(demodir)/Makefile*

uninstall-local:
	rm -rf $(DESTDIR)$(demodir)

clean-local:
	true
