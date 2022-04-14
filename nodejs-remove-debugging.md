# NodeJS remove debugging

### STEP 1.&#x20;

Download the code

```
rsync -az --compress-level=1 student@chips:/home/student/chips/ chips/
```



### STEP 2.

A .vscode/launch.json

```json
{

	"version": "0.2.0",
	"configurations": [
		{
			"type": "node",
			"request": "attach",
			"name": "Attach to remote",
			"address": "{{ IP HERE }}",
			"port": 9229,
			"localRoot": "${workspaceFolder}",
			"remoteRoot": "/usr/src/app"
		},
		{
			"type": "node",
			"request": "attach",
			"name": "Attach to remote (cli)",
			"address": "{{ IP HERE }}",
			"port": 9228,
			"localRoot": "${workspaceFolder}",
			"remoteRoot": "/usr/src/app"
		}
	]
}
```



### STEP 3.

Then start nodejs server with:

```bash
node --inspect=0.0.0.0:9228
```
