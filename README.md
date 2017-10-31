# XMR-Stak-POWER - Monero mining software for POWER8 and later

XMR-Stak-POWER is a universal Stratum pool miner and a for of XMR-Stak-CPU. There is also an [AMD GPU version](https://github.com/fireice-uk/xmr-stak-amd) and an [NVIDA GPU version](https://github.com/fireice-uk/xmr-stak-nvidia)

## HTML and JSON API report configuraton

To configure the reports shown above you need to edit the httpd_port variable. Then enable wifi on your phone and navigate to [miner ip address]:[httpd_port] in your phone browser. If you want to use the data in scripts, you can get the JSON version of the data at url [miner ip address]:[httpd_port]/api.json

XMR-Stak-POWER will currently only compile with the GCC 6.3.1 compiler included in the IBM AT10.0 developer tools. [IBM Advance Toolchain](https://www.ibm.com/developerworks/community/wikis/home?lang=en#!/wiki/W51a7ffcf4dfd_4b40_9d82_446ebc23c550/page/IBM Advance Toolchain for PowerLinux Documentation)
## Compile guides

- [Linux](LINUXCOMPILE.md)

#### CPU mining performance 

Here are some numbers:

* **Dual POWER8 10C @ 2.8GHz, running 3 threads per core** - 1600 H/s

## Default dev donation
By default the miner will donate 0.88% of the hashpower.
If you have POWER hardware available you are probably rich, so please donate to my address!

nioroso-x3:
```
42UwBFuWj9uM7RjH15MXAFV7oLWUC9yLTArz4bmD3gbVWu1obYRUDe8K9v8StqXPhP2Uz1BJZgDQTUVhvT1cHFMBHA6aPg2
```

Original developers:

fireice-uk:
```
4581HhZkQHgZrZjKeCfCJxZff9E3xCgHGF25zABZz7oR71TnbbgiS7sK9jveE6Dx6uMs2LwszDuvQJgRZQotdpHt1fTdDhk
```

psychocrypt:
```
43NoJVEXo21hGZ6tDG6Z3g4qimiGdJPE6GRxAmiWwm26gwr62Lqo7zRiCJFSBmbkwTGNuuES9ES5TgaVHceuYc4Y75txCTU
```

## Advanced Compile Options

The build system is CMake, if you are not familiar with CMake you can learn more [here](https://cmake.org/runningcmake/).

### Short Description

There are two easy ways to set variables for `cmake` to configure *xmr-stak-cpu*
- use the ncurses GUI
  - `ccmake .`
  - edit your options
  - end the GUI by pressing the key `c`(create) and than `g`(generate)
- set Options on the command line
  - enable a option: `cmake . -DNAME_OF_THE_OPTION=ON`
  - disable a option `cmake . -DNAME_OF_THE_OPTION=OFF`
  - set a value `cmake . -DNAME_OF_THE_OPTION=value`

After the configuration you need to call
`make install` for slow sequential build
or
`make -j install` for faster parallel build
and install.

### xmr-stak-cpu Compile Options
- `CMAKE_INSTALL_PREFIX` install miner to the home folder
  - `cmake . -DCMAKE_INSTALL_PREFIX=$HOME/xmr-stak-cpu`
  - you can find the binary and the `config.txt` file after `make install` in `$HOME/xmr-stak-cpu/bin`
- `CMAKE_LINK_STATIC` link libgcc and libstdc++ libraries static (default OFF)
  - disable with `cmake . -DCMAKE_LINK_STATIC=ON`
-`CMAKE_BUILD_TYPE` set the build type
  - valid options: `Release` or `Debug`
  - you should always keep `Release` for your productive miners
- `MICROHTTPD_ENABLE` allow to disable/enable the dependency *microhttpd*
  - by default enabled
  - there is no *http* interface available if option is disabled: `cmake . -DMICROHTTPD_ENABLE=OFF`
- `OpenSSL_ENABLE` allow to disable/enable the dependency *OpenSSL*
  - by default enabled
  - it is not possible to connect to a *https* secured pool if option is disabled: `cmake . -DOpenSSL_ENABLE=OFF`
- `HWLOC_ENABLE` allow to disable/enable the dependency *hwloc*
  - by default enabled
  - the config suggestion is not optimal if option is disabled: `cmake . -DHWLOC_ENABLE=OFF`

