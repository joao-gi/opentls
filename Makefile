SHELL := /bin/bash

deps:
	pip install --upgrade --use-mirrors \
	            -r requirements/development.txt \
	            -r requirements/testing.txt \
	            -r requirements/production.txt

lint:
	flake8 --exit-zero tls/c/*py
	flake8 --exit-zero tls/io/*py
	flake8 --exit-zero tls/*py

dist:
	python setup.py sdist

site:
	cd docs; make html

test:
	coverage run setup.py test

unittest:
	coverage run -m unittest2 discover

coverage:
	coverage report --include="tls*"

clean:
	python setup.py clean --all
	find . -type f -name "*.pyc" -exec rm '{}' +
	find . -type d -name "__pycache__" -exec rm -rf '{}' +
	rm -rf *.egg-info .coverage
	cd docs; make clean

docs: site
