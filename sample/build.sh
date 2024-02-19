set -x
aarch64-linux-gnu-gcc -fPIC -shared sample_patch.cpp -I${TARGET_TMPROOTFS_DIR}/include/ -L${TARGET_TMPROOTFS_DIR}/lib/ -lalog -o sample_patch.so
aarch64-linux-gnu-gcc -fPIC -shared helper_hook.cpp -I${TARGET_TMPROOTFS_DIR}/include/ -L${TARGET_TMPROOTFS_DIR}/lib/ -lalog -o helper_hooker.so
aarch64-linux-gnu-gcc -fPIC -shared test_lib.cpp -o libtest_lib.so
#Use -Wl,-dynamic-list,dynsym.syms,-Wl,-E(all to .dynsym), make so can access exectable file's symbol(dlopen)
aarch64-linux-gnu-gcc -fPIC test.cpp -I${TARGET_TMPROOTFS_DIR}/include/ -L${TARGET_TMPROOTFS_DIR}/lib/ -L./ -Wl,-dynamic-list,dynsym.syms -ltest_lib -lalog -o test.elf
