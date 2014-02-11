all: docs
	doxygen janus-doxygen.cfg
	cp doxy-boot.js html/
	cp ../html/jquery.min.js html/jquery.js
	cp dynsections.js html/
	mkdir -p html/css
	cp ../html/css/cerulean/bootstrap.css html/css/
	cp ../html/css/demo.css html/css/
	mkdir -p html/js
	cp ../html/js/bootstrap.min.js html/js/
	cp ../html/favicon.ico html/

docs:
	true
	
clean:
	rm -rf html
