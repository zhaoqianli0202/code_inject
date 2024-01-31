set -x
aarch64-linux-gnu-gcc -fPIC -shared sample_patch.cpp -I/home/qianli.zhao/matrix5/out/debug-gcc_9.3-64/target/rootfs/include/ -L/home/qianli.zhao/matrix5/out/debug-gcc_9.3-64/target/deploy/system/lib -lalog -o sample_patch.so
aarch64-linux-gnu-gcc -fPIC -shared helper_hook.cpp -I/home/qianli.zhao/matrix5/out/debug-gcc_9.3-64/target/rootfs/include/ -L/home/qianli.zhao/matrix5/out/debug-gcc_9.3-64/target/deploy/system/lib -lalog -o helper_hooker.so
aarch64-linux-gnu-gcc -fPIC -shared test_lib.cpp -o libtest_lib.so
aarch64-linux-gnu-gcc -fPIC test.cpp -I/home/qianli.zhao/matrix5/out/debug-gcc_9.3-64/target/rootfs/include/ -L/home/qianli.zhao/matrix5/out/debug-gcc_9.3-64/target/deploy/system/lib -L./ -ltest_lib -lalog -o test.elf
