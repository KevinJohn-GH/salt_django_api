.PHONY: initial

salt_image:
	docker build -t salt:django_api .

salt_network:
	 docker network create --subnet=172.19.0.0/16 salt_django_api

master_container:
	docker run -d -p 8022:22 -p 8080:8080 -v volumes/master.d:/etc/salt/master.d --name=salt_django_api --net salt_django_api --ip 172.19.0.2 --hostname salt_django_api salt:django_api