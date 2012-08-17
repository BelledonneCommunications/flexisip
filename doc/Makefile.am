guide=flexisip_guide
guide_tex=$(srcdir)/${guide}.tex
guide_pdf=$(top_builddir)/doc/${guide}.pdf

docfiles=$(guide_tex)

if GENERATE_DOC
docfiles +=$(guide_pdf)

CLEANFILES = *.log *.toc *.out *.log *.tmp ${guide_pdf} *.aux *.tmp.tex

${guide_pdf}: $(srcdir)/${guide}.tex $(top_builddir)/src/flexisip
	sh latex_include_generator.sh
# Several times to make sure the TOC is up-to-date
	- pdflatex --interaction=nonstopmode  "\newcommand\flexisipversion{ ${VERSION}}\input{${guide}}"
	- pdflatex --interaction=nonstopmode  "\newcommand\flexisipversion{ ${VERSION}}\input{${guide}}"
	- pdflatex --interaction=nonstopmode  "\newcommand\flexisipversion{ ${VERSION}}\input{${guide}}"

fldocdir=$(datadir)/doc/$(PACKAGE)-$(VERSION)
fldoc_DATA = $(docfiles) $(srcdir)/schem*.pdf $(srcdir)/latex_include_generator.sh $(srcdir)/schem*.svg $(srcdir)/*.png

endif

dist_doc_DATA=$(guide_tex) $(srcdir)/schem*.pdf $(srcdir)/latex_include_generator.sh $(srcdir)/schem*.svg $(srcdir)/*.png
