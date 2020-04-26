

docker build \
	--file Dockerfile.mysite-root \
	--tag mysite-static:latest \
	.

docker build \
	--file Dockerfile.hello-flask \
	--tag myflask:latest \
	.

docker build \
	--file Dockerfile.yoursite-root \
	--tag yoursite-static:latest \
	.
