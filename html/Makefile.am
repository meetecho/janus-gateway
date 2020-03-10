demodir = $(datadir)/janus/demos

html-local:
	true

install-data-local: html-local
	$(MKDIR_P) $(DESTDIR)$(demodir)
	cp -r * $(DESTDIR)$(demodir)
	rm -f $(DESTDIR)$(demodir)/Makefile*

uninstall-local:
	rm -rf $(DESTDIR)$(demodir)

clean-local:
	true
