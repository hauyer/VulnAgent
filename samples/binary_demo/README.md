# Binary Demo

The repository stores source rather than a platform-specific executable.

```bash
cc -O0 -o samples/binary_demo/vulnerable samples/binary_demo/vulnerable.c
```

Analyze the compiled PE/ELF through a binary task. The built-in analyzer reads
headers, imports and bounded strings without executing the target. radare2 and
UPX are optional adapters; unavailable tools must be reported as unavailable.
