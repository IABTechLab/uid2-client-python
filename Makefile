DOCKERIMAGE = uid_client_python

test:
	docker run -t -w $(PWD) -v $(PWD):$(PWD) -u `id -u`:`id -g` $(DOCKERIMAGE) python3 -m unittest tests/*.py $(TESTARGS)

shell:
	docker run -it -w $(PWD) -v $(PWD):$(PWD) -u `id -u`:`id -g` $(DOCKERIMAGE) /bin/bash

examples: example_client example_auto_refresh example_sharing

example_client:
	docker run -w $(PWD) -v $(PWD):$(PWD) -u `id -u`:`id -g` -e PYTHONPATH=$(PWD) $(DOCKERIMAGE) python3 examples/sample_client.py "$(BASE_URL)" "$(AUTH_KEY)" "$(SECRET_KEY)" "$(AD_TOKEN)"

example_auto_refresh:
	docker run -w $(PWD) -v $(PWD):$(PWD) -u `id -u`:`id -g` -e PYTHONPATH=$(PWD) $(DOCKERIMAGE) python3 examples/sample_auto_refresh.py "$(BASE_URL)" "$(AUTH_KEY)" "$(SECRET_KEY)" "$(AD_TOKEN)"

example_encryption:
	docker run -w $(PWD) -v $(PWD):$(PWD) -u `id -u`:`id -g` -e PYTHONPATH=$(PWD) $(DOCKERIMAGE) python3 examples/sample_encryption.py "$(BASE_URL)" "$(AUTH_KEY)" "$(SECRET_KEY)" "$(AD_TOKEN)" "Hello World!"

example_sharing:
	docker run -w $(PWD) -v $(PWD):$(PWD) -u `id -u`:`id -g` -e PYTHONPATH=$(PWD) $(DOCKERIMAGE) python3 examples/sample_sharing.py "$(BASE_URL)" "$(AUTH_KEY)" "$(SECRET_KEY)" "$(RAW_UID)"


docker:
	docker build -t $(DOCKERIMAGE) -f Dockerfile.dev .

wheel:
	docker run -t -w $(PWD) -v $(PWD):$(PWD) -u `id -u`:`id -g` $(DOCKERIMAGE) python3 setup.py bdist_wheel

.PHONY: test shell example example_client example_auto_refresh example_encryption docker wheel
