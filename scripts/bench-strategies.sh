#!/bin/sh
# bench-strategies.sh — прогнать стратегии nfqws2 через детектор и выбрать подходящую.
#
# Запускается НА РОУТЕРЕ (Entware/BusyBox sh). Для каждой стратегии:
#
#   1) убирает из неё позитивные фильтры по спискам — `--hostlist=`,
#      `--hostlist-auto=`, `--hostlist-domains=`, `--ipset=` — чтобы десинк
#      применялся ко всему трафику, а не к перечисленным целям. Исключения
#      (`--hostlist-exclude=`, `--ipset-exclude=`) остаются: они расширяют
#      обработку, а не сужают её;
#   2) подставляет реальный интерфейс провайдера вместо того, что написан в
#      стратегии (`eth3` и подобные заглушки авторов);
#   3) ставит `NFQWS_EXTRA_ARGS="$MODE_ALL"` — режим работы перестаёт добавлять
#      свой список, но штатные исключения пакета сохраняются;
#   4) перезапускает nfqws2 и ждёт, пока очередь поднимется;
#   5) прогоняет детектор с тестом доменов (`--json`, тест 2) и разбирает
#      результат: сколько проверок из скольких прошло и чем падали остальные;
#   6) возвращает исходный конфиг — в конце, при любом выходе, включая Ctrl+C.
#
# В конце печатает таблицу и складывает её в results.tsv рядом с JSON-ами.
#
# Использование:
#   bench-strategies.sh [-s DIR] [-b PATH] [-d FILE] [-o DIR] [-w SEC]
#
#   -s DIR   каталог со стратегиями            (по умолчанию /opt/etc/nfqws2/strategies)
#   -b PATH  бинарь детектора                  (по умолчанию /opt/bin/dpi-detector)
#   -d FILE  файл со доменами, по одному в строке
#            (по умолчанию — встроенный список детектора, 34 домена: долго)
#   -o DIR   куда класть JSON и results.tsv    (по умолчанию /tmp/strategy-bench)
#   -w SEC   сколько ждать подъёма службы      (по умолчанию 5)
#   -r N     сколько раз прогнать детектор на каждой стратегии и взять лучший
#            результат (по умолчанию 1: у DPI есть разброс между прогонами)
#
# Пример на 10 доменах:
#   printf '%s\n' www.youtube.com discord.com gateway.discord.gg \
#       www.instagram.com www.facebook.com x.com meduza.io \
#       www.torproject.org nnmclub.to www.dw.com > /tmp/bench-domains.txt
#   sh bench-strategies.sh -d /tmp/bench-domains.txt

set -u

STRAT_DIR=/opt/etc/nfqws2/strategies
BIN=/opt/bin/dpi-detector
DOMAINS=""
OUT=/tmp/strategy-bench
WAIT=5
RUNS=1

CONF=/opt/etc/nfqws2/nfqws2.conf
SERVICE=/opt/etc/init.d/S51nfqws2
PIDFILE=/opt/var/run/nfqws2.pid
QUEUE=/proc/net/netfilter/nfnetlink_queue
BACKUP=/tmp/bench-strategies-orig.conf
PATCHED=/tmp/bench-strategies.conf
BENCH_PID=/tmp/bench-strategies.pid

usage() {
    sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while getopts "s:b:d:o:w:r:h" opt; do
    case "$opt" in
        s) STRAT_DIR=$OPTARG ;;
        b) BIN=$OPTARG ;;
        d) DOMAINS=$OPTARG ;;
        o) OUT=$OPTARG ;;
        w) WAIT=$OPTARG ;;
        r) RUNS=$OPTARG ;;
        h) usage 0 ;;
        *) usage 1 ;;
    esac
done

[ -d "$STRAT_DIR" ] || { echo "нет каталога со стратегиями: $STRAT_DIR" >&2; exit 1; }
[ -x "$BIN" ] || { echo "нет детектора: $BIN" >&2; exit 1; }
[ -f "$DOMAINS" ] && [ ! -r "$DOMAINS" ] && { echo "нет файла доменов: $DOMAINS" >&2; exit 1; }
[ -f "$SERVICE" ] || { echo "нет службы nfqws2: $SERVICE" >&2; exit 1; }

mkdir -p "$OUT" || exit 1

# Интерфейс, которым роутер выходит наружу: в стратегиях на его месте заглушка.
# Поле после `dev`, а не по номеру: у Keenetic строка выглядит как
# `default dev ppp0  scope link  metric 1000`, и пятое поле тут — `link`.
IFACE=$(ip route show default 2>/dev/null |
    awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
[ -n "$IFACE" ] || IFACE=$(route -n 2>/dev/null | awk '$1 == "0.0.0.0" {print $8; exit}')
[ -n "$IFACE" ] || { echo "не удалось определить интерфейс провайдера" >&2; exit 1; }

restore() {
    if [ -f "$BACKUP" ]; then
        cp "$BACKUP" "$CONF"
        "$SERVICE" restart >/dev/null 2>&1
        rm -f "$BACKUP" "$PATCHED" "$BENCH_PID"
        if sh -n "$CONF" 2>/dev/null; then
            echo "конфиг возвращён, служба перезапущена"
        else
            echo "ВНИМАНИЕ: возвращённый конфиг не проходит проверку" >&2
        fi
    fi
}
trap 'restore; exit 130' INT TERM
trap 'restore' EXIT

# Бэкап делается один раз за всё время: если он уже лежит (прошлый прогон
# прервали), в нём исходный конфиг, и перезаписывать его текущим — уже
# подменённым стратегией — нельзя, иначе восстанавливать будет нечего.
if [ -f "$BACKUP" ]; then
    echo "найден бэкап прошлого прогона: $BACKUP (в нём исходный конфиг)"
else
    cp "$CONF" "$BACKUP" || exit 1
fi
echo $$ > "$BENCH_PID"
echo "интерфейс: $IFACE | стратегии: $STRAT_DIR | детектор: $BIN"
[ -n "$DOMAINS" ] && echo "домены: $DOMAINS" || echo "домены: встроенный список детектора"
[ "$RUNS" -gt 1 ] && echo "прогонов на стратегию: $RUNS (в таблице — лучший)"
echo

# Очередь поднялась? Пока в ней нет строки с нашим номером, nfqws2 ещё не готов.
queue_ready() {
    qnum=$(grep -m1 '^NFQUEUE_NUM=' "$CONF" | cut -d= -f2)
    [ -n "$qnum" ] || return 1
    awk -v q="$qnum" '$1 == q {found = 1} END {exit !found}' "$QUEUE" 2>/dev/null
}

# Позитивные фильтры по спискам — вон; исключения остаются.
#
# Кавычку в набор исключений добавили не зря: список часто стоит последним в
# строке (`MODE_LIST="--hostlist=…"`), и шаблон без неё съедает закрывающую
# кавычку — конфиг становится невалидным, служба не поднимается. Проверка
# `sh -n` в вызывающем коде ловит такой патч до установки.
patch_strategy() {
    tr -d '\r' < "$1" |
        sed -e 's/--hostlist=[^[:space:]"]*//g' \
            -e 's/--hostlist-auto=[^[:space:]"]*//g' \
            -e 's/--hostlist-domains=[^[:space:]"]*//g' \
            -e 's/--ipset=[^[:space:]"]*//g' \
            -e "s|^ISP_INTERFACE=.*|ISP_INTERFACE=\"$IFACE\"|" \
            -e 's|^NFQWS_EXTRA_ARGS=.*|NFQWS_EXTRA_ARGS="$MODE_ALL"|' > "$PATCHED"
}

# Сколько позитивных фильтров осталось в том, что реально получит демон.
list_filters_left() {
    sh -c ". $SERVICE >/dev/null 2>&1; _startup_args" 2>/dev/null |
        tr ' ' '\n' |
        grep -cE '^--(hostlist|hostlist-auto|hostlist-domains|ipset)='
}

# Одна проверка: сколько полей `ok` из скольких и чем падало остальное.
# JSON детектора напечатан с отступами, поэтому после двоеточия есть пробел.
summarize() {
    json=$1
    total=$(( $(grep -oE '"tls13":' "$json" | wc -l) * 3 ))
    if [ "$total" -eq 0 ]; then
        printf -- '-\t-\t-\t-\t-\tнет данных\n'
        return
    fi
    http=$(grep -oE '"http":[[:space:]]*"ok"' "$json" | wc -l)
    tls12=$(grep -oE '"tls12":[[:space:]]*"ok"' "$json" | wc -l)
    tls13=$(grep -oE '"tls13":[[:space:]]*"ok"' "$json" | wc -l)
    fails=$(grep -oE '"(http|tls12|tls13)":[[:space:]]*"[a-z_0-9]*"' "$json" |
        sed 's/.*"\([a-z_0-9]*\)"$/\1/' |
        grep -v '^ok$' |
        sort | uniq -c | sort -rn | head -2 |
        awk '{printf "%s x%s ", $2, $1}')
    [ -n "$fails" ] || fails='-'
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(( http + tls12 + tls13 ))" "$total" "$http" "$tls12" "$tls13" "$fails"
}

: > "$OUT/results.tsv"
printf 'стратегия\tзапуск\tсписков\tok\tвсего\thttp\ttls12\ttls13\tчем падало\n' > "$OUT/table.tsv"

for strategy in "$STRAT_DIR"/*.conf; do
    [ -f "$strategy" ] || continue
    name=$(basename "$strategy" .conf)
    printf '%-22s ' "$name"

    patch_strategy "$strategy"
    if ! sh -n "$PATCHED" 2>/dev/null; then
        echo "патч сломал конфиг — стратегия пропущена"
        printf '%s\tнет\t-\t-\t-\t-\t-\t-\tконфиг после правки невалиден\n' "$name" >> "$OUT/table.tsv"
        continue
    fi
    cp "$PATCHED" "$CONF"
    "$SERVICE" restart >/dev/null 2>&1

    ready=no
    i=0
    while [ "$i" -lt "$WAIT" ]; do
        sleep 1
        if [ -f "$PIDFILE" ] && queue_ready; then
            ready=yes
            break
        fi
        i=$((i + 1))
    done

    if [ "$ready" = no ]; then
        echo "не запустилась (нет очереди за ${WAIT}с)"
        printf '%s\tнет\t-\t-\t-\t-\t-\t-\tслужба не поднялась\n' "$name" >> "$OUT/table.tsv"
        continue
    fi

    left=$(list_filters_left)
    best=""
    best_ok=-1
    run=1
    while [ "$run" -le "$RUNS" ]; do
        json="$OUT/$name.$run.json"
        # Детектор запускается из чистого каталога: config.yml ищется в текущем,
        # а рядом с ним мог остаться чужой от прошлых прогонов.
        if [ -n "$DOMAINS" ]; then
            ( cd "$OUT" && "$BIN" --json -t 2 --domains "$DOMAINS" ) > "$json" 2>"$OUT/$name.$run.err"
        else
            ( cd "$OUT" && "$BIN" --json -t 2 ) > "$json" 2>"$OUT/$name.$run.err"
        fi
        if grep -q '"domain_inspection"' "$json"; then
            summary=$(summarize "$json")
            ok=$(echo "$summary" | cut -f1)
            if [ "$ok" != '-' ] && [ "$ok" -gt "$best_ok" ]; then
                best_ok=$ok
                best=$summary
            fi
        fi
        run=$((run + 1))
    done

    if [ -z "$best" ]; then
        echo "детектор не дал результатов (см. $name.1.err)"
        printf '%s\tда\t%s\t-\t-\t-\t-\t-\tнет данных\n' "$name" "$left" >> "$OUT/table.tsv"
        continue
    fi

    summary=$best
    ok=$(echo "$summary" | cut -f1)
    total=$(echo "$summary" | cut -f2)
    echo "$ok/$total"
    printf '%s\tда\t%s\t%s\n' "$name" "$left" "$summary" >> "$OUT/table.tsv"
done

# Таблица: сначала те, у кого больше прошло. Число выносится вперёд и
# сортируется как первое поле — `sort -t` с табуляцией BusyBox понимает
# не всегда, а слитную форму `-k1,1nr` он молча игнорирует: нужны отдельные
# `-k1,1` и `-nr`.
{
    head -1 "$OUT/table.tsv"
    tail -n +2 "$OUT/table.tsv" |
        awk -F'\t' '{print ($4 == "-" ? -1 : $4) "\t" $0}' |
        sort -k1,1 -nr |
        cut -f2-
} > "$OUT/table.sorted.tsv"

echo
echo "================ результаты (ok — сколько проверок прошло) ================"
awk -F'\t' '
    BEGIN {
        printf "%-22s %-7s %-8s %-11s %-5s %-6s %-6s %s\n",
               "стратегия", "запуск", "списков", "ok", "http", "tls12", "tls13", "чем падало"
        printf "%-22s %-7s %-8s %-11s %-5s %-6s %-6s %s\n",
               "----------------------", "-------", "--------", "-----------", "-----", "------", "------", "----------"
    }
    NR == 1 { next }
    {
        score = ($4 == "-" || $5 == "-") ? "нет данных" : $4 "/" $5
        printf "%-22s %-7s %-8s %-11s %-5s %-6s %-6s %s\n", $1, $2, $3, score, $6, $7, $8, $9
    }' "$OUT/table.sorted.tsv"

best=$(tail -n +2 "$OUT/table.sorted.tsv" | awk -F'\t' '$4 != "-" {print $1; exit}')
echo
[ -n "$best" ] && echo "лучшая по числу пройденных проверок: $best"
echo "таблица: $OUT/table.sorted.tsv | JSON-ы и stderr: $OUT/"
