# SIMPLE X86-64 LINUX NON POSIX SANDBOX

Using `Namespaces` in Linux. <br/>
This works as a preloaded shared lib <br/>

- It first takes your application, preloads the shared lib to set up the sandbox
- Then it runs your applications' `main(int,char\*\*)`

# RUN

- this will compile `main.cpp` and the preload shared lib and run them together
- this gives you a shell to play around with

```bash
    make
```

- Manual : replace `<executable>` executable with your executable

```bash
make lib
LD_PRELOAD=./lib/libpreload.so <executable>
```
