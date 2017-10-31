# Compile **xmr-stak** for Linux

### GNU Compiler
```
    # CentOS
    #Install the IBM Advance Toolchain 10.0, set your CC and CXX variables to the installed compilers, and compile like any CMake program.
    $ cd $(your_build_dir)
    $ cmake $(source_code_dir)
    $ make 
    $ make install
```

- IBM g++ version 6.3.1 is required.

Note - cmake caches variables, so if you want to do a dynamic build later you need to specify '-DCMAKE_LINK_STATIC=OFF'



