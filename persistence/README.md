# Persistence

## Windows

Cobalt Strike doesn't include any built-in commands specifically for persistence. [SharPersist](https://github.com/fireeye/SharPersist) is a Windows persistence toolkit written by FireEye. It's written in C#, so can be executed via `execute-assembly`.

* `-t` is the desired persistence technique.
* `-c` is the command to execute.
* `-a` are any arguments for that command.
* `-n` is the name of the task.
* `-m` is to add the task (you can also `remove`, `check` and `list`).
* `-o` is the task frequency
