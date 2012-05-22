guide=flexisip_guide
docfiles =${guide}.tex

if GENERATE_DOC

CLEANFILES = *.log *.toc *.out *.log *.tmp ${guide}.pdf *.aux *.tmp.tex

BASE_DIR=$(shell pwd)/..

${guide}.pdf: $(srcdir)/${guide}.tex $(BASE_DIR)/src/flexisip
	sh latex_include_generator.sh
# Several times to get sure the TOC is up-to-date
	pdflatex   "\newcommand\flexisipversion{ ${VERSION}}\input{${guide}}"
	pdflatex   "\newcommand\flexisipversion{ ${VERSION}}\input{${guide}}"
	pdflatex   "\newcommand\flexisipversion{ ${VERSION}}\input{${guide}}"

dist_doc_DATA = $(docfiles)

endif
