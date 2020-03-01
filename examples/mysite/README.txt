To build & run the flask service


	$ docker build -f Dockerfile.hello-flask . -t myflask:latest
	$ docker run -p 5000:5000 myflask:latest
