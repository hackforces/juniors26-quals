# Исполняется ДО включения ограничений rbash.
export PATH=/home/level3/bin
export SHELL=/bin/bash
export PS1='envelope-3$ '
# потолок процессов на пользователя (fork bomb)
ulimit -u 128 2>/dev/null || true
