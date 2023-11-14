docker build -t vulndb:basic -f Dockerfile-basic .
docker build -t vulndb:nvd -f Dockerfile-update-nvd .
docker build -t vulndb:nvd-osv -f Dockerfile-update-nvd2osv .
docker tag vulndb:nvd-osv vulndb
