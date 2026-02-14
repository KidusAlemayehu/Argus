# Argus

The hundred-eyed sentinel for your terminal._

Argus watches every command before execution, detecting
Unicode confusables, invisible characters, and dangerous
patterns like `curl | bash`.

## Build
```bash
make
./argus "string1" "string2"

