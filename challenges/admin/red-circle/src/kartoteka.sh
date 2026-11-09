#!/bin/bash
# КАРТОТЕКА v1.0 — «защищённая» оболочка пятого конверта (level 5).
export PATH=/usr/bin:/bin
export SHELL=/usr/local/bin/kartoteka
# потолок процессов на пользователя (fork bomb)
ulimit -u 128 2>/dev/null || true

echo "======================================================"
echo " КАРТОТЕКА v1.0 — защищённый архив пятого конверта"
echo "======================================================"
echo " Доступные команды:"
echo "   ls [каталог]   — показать файлы"
echo "   date           — дата и время"
echo "   whoami         — кто я"
echo "   find ШАБЛОН    — найти файлы в /home/level5"
echo "   help           — справка"
echo "   quit           — выход"
echo ""
echo " ЦЕЛЬ: запустить /usr/local/bin/nextkey — он печатает ключ."
echo " Подробности — в README.txt."
echo "======================================================"

while true; do
    printf 'kartoteka> '
    read -r cmd args || { echo; exit 0; }
    case "$cmd" in
        help)
            cat <<'HLP'
ls [каталог]   — показать файлы
date           — дата и время
whoami         — кто я
find ШАБЛОН    — найти файлы в /home/level5
quit           — выход
HLP
            ;;
        ls)     /bin/ls $args ;;
        date)   /bin/date ;;
        whoami) id -un ;;
        find)   /usr/bin/find /home/level5 $args ;;
        quit|exit) exit 0 ;;
        '')     : ;;
        *)      echo "картотека: команда не разрешена: $cmd" ;;
    esac
done
