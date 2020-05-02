#!/bin/bash


pushd examples/mysite
sh build.sh
cleat setup -f config.yaml
cleat update-ssl -f config.yaml
cleat run -f config.yaml
popd
