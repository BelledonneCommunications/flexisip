#Copying and distribution of this file, with or without modification,
#are permitted in any medium without royalty provided the copyright
#notice and this notice are preserved.  This file is offered as-is,
#without any warranty

EXTRA_DIST=	latex_include_generator.sh \
		schema_archi_flexisip_active-active.pdf \
		schema_archi_flexisip_dead-active.pdf \
		schema_archi_flexisip_active-active.svg \
		schema_archi_flexisip_dead-active.svg \
		bc_logo.png \
		GFDL.txt \
		README

guide=flexisip_guide
guide_tex=$(srcdir)/${guide}.tex
guide_pdf=$(top_builddir)/doc/${guide}.pdf

docfiles=$(guide_tex) $(top_srcdir)/AUTHORS $(top_srcdir)/COPYING $(top_srcdir)/ChangeLog $(top_srcdir)/NEWS $(top_srcdir)/README

if GENERATE_DOC
docfiles +=$(guide_pdf)

CLEANFILES = *.log *.toc *.out *.log *.tmp ${guide_pdf} *.aux *.tmp.tex

${guide_pdf}: $(srcdir)/${guide}.tex $(top_builddir)/src/flexisip
	$(srcdir)/latex_include_generator.sh
# Several times to make sure the TOC is up-to-date
	- pdflatex --interaction=nonstopmode  "\newcommand\flexisipversion{ $(VERSION)}\input{$(guide_tex)}"
endif

fldocdir=$(datadir)/doc/$(PACKAGE)-$(VERSION)
fldoc_DATA = $(docfiles)

dist_fldoc_DATA=$(guide_tex)



