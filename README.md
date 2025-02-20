# SIMPLE X86-64 LINUX NON POSIX SANDBOX

Using `Namespaces` in Linux. <br/>
This works as a preloaded shared lib <br/>

- It first takes your application's `_libc_start_main`, preloads the shared lib to set up the sandbox
- Does this by overriding the `__libc_start_main` and `main(int,char**)` setting up the sandbox before calling the next `main(int,char**)` which belongs to the lib
- Then it runs your applications' `main(int,char**)`

# RUN

- this will compile `main.cpp` and the preload shared lib and run them together
- this gives you a shell to play around with

```bash
    make
```

- Manual : in the makefilem replace `<executable>` executable with your executable

```bash
make lib
LD_PRELOAD=./lib/libpreload.so <executable>
```
