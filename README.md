# json2dir-asm

json2dir in x86-64 Linux assembly (MASM syntax, assembled with [JWasm](https://github.com/Baron-von-Riedesel/JWasm)): raw syscalls, a hand-written ELF header, no libc, no linker.

    jwasm -q -bin -Fo=json2dir.bin json2dir.asm && mv json2dir.bin json2dir && chmod +x json2dir
    ./json2dir < document.json
