PROGRAM=spurge
VERSION=0.5.1

TARBALLFILES=Makefile spurge.conf spurge.sgml vault.conf installer\
             example-motd sbin-spurge spurge.py spurge.8 \
             README COPYING

dummy:
	@echo "Please use 'make install' to install $(PROGRAM)."

install: doc
	@python installer install

uninstall:
	@python installer uninstall

test:
	@echo "Sorry, the test script didn't make the final cut."
	@echo "It should be available in a future version."

################################################################

doc: spurge.8

spurge.8: spurge.sgml
	docbook-to-man $< > $@

################################################################

tar: spurge-$(VERSION).tar.gz spurge-$(VERSION).tar.bz2

spurge-$(VERSION).tar.gz: spurge.8 $(TARBALFILES)
	mkdir arcing
	mkdir arcing/spurge-$(VERSION)
	cp $(TARBALLFILES) arcing/spurge-$(VERSION)
	tar czf spurge-$(VERSION).tar.gz -C arcing spurge-$(VERSION)
	rm -rf arcing

spurge-$(VERSION).tar.bz2: spurge.8 $(TARBALFILES)
	mkdir arcing
	mkdir arcing/spurge-$(VERSION)
	cp $(TARBALLFILES) arcing/spurge-$(VERSION)
	tar cjf spurge-$(VERSION).tar.bz2 -C arcing spurge-$(VERSION)
	rm -rf arcing

################################################################

clean:
	-rm -f spurge.8 spurge.pyc *~ spurge-$(VERSION).tar.*

################################################################
