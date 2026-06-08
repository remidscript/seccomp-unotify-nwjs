# Seccomp User Notify wrapper over NW.js
A **Linux** user program in C that wrap around and executes `nw` with target directory the user entered as the first argument.

## Status
This project only successfully intercepts openat syscalls but couldn't be used to fully emulate as a file opener. So this is archived here as just an example for using Seccomp User Notify.

### Building
Just call build.sh and the `hook` executable should come out in the same directory.
### Usage
Your system must have NW.js installed as `nw` in **PATH**. Then call the hook executable with the first argument being the NW.js project directory. Example: `/path/to/hook /path/to/rpgmaker-mv-mz-game`


