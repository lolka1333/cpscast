#!/bin/sh
# Periodic captioncast runner for the RV6699 (busybox ash).
#
#   start:   /var/ccloop.sh start [interval_seconds]     (default 120)
#   stop:    /var/ccloop.sh stop
#   status:  /var/ccloop.sh status
#   log:     tail -40 /var/captioncast.log
#
# Deliberately depends on almost nothing: this busybox has no `wc`, and its `nc`
# lacks -z, so reachability is decided by captioncast's own --status output and
# the log is trimmed by line count with `tail`. /var is a ramfs - see the note
# at the bottom about surviving a reboot.

BIN=/var/captioncast
MEDIA=/var/media.mp4
TV=192.168.1.70
LOG=/var/captioncast.log
STATS=/var/ccstats.log   # one compact line per run; the verbose log is trimmed
PIDF=/var/ccloop.pid
KEEP=400                 # lines of log to keep; ramfs is precious
KEEPSTATS=2000           # ~a day of runs at 2 min

tv_awake() {
    # --status is read-only. If the renderer answered, the line carries a real
    # transport state; when it is unreachable the field comes back as "?".
    out=$("$BIN" --tv "$TV" --status 2>/dev/null)
    case "$out" in
        *"state=?"*) return 1 ;;
        *state=*)    return 0 ;;
        *)           return 1 ;;
    esac
}

loop() {
    interval=$1
    while :; do
        if tv_awake; then
            tmp=/var/cc.run.$$
            echo "===== $(date) run =====" >> "$LOG"
            "$BIN" --tv "$TV" --media "$MEDIA" --nopoll > "$tmp" 2>&1
            cat "$tmp" >> "$LOG"
            # One line per run so the interesting correlation survives the log
            # trim: did it play, how far, and did the TV abandon the first
            # stream and seek to a non-zero offset (which so far only ever
            # happens on the runs that fail).
            # Parsed with shell builtins only: this busybox has no sed, no wc
            # and no head. `case` globbing plus ${var#pattern} is all we need.
            st="state=?"; pos="?"; seek=no
            while read -r line; do
                case "$line" in
                    *state=PLAYING*)       st="state=PLAYING" ;;
                    *state=TRANSITIONING*) st="state=TRANSITIONING" ;;
                    *state=STOPPED*)       st="state=STOPPED" ;;
                esac
                case "$line" in
                    *Range=bytes=[1-9]*)   seek=yes ;;
                esac
                case "$line" in
                    *pos=*) p=${line#*pos=}; p=${p%% *}; pos=${p%%/*} ;;
                esac
            done < "$tmp"
            echo "$(date '+%m-%d %H:%M:%S') $st pos=$pos seek=$seek" >> "$STATS"
            rm -f "$tmp"
        else
            echo "$(date) TV not answering, skipping" >> "$LOG"
            echo "$(date '+%m-%d %H:%M:%S') asleep" >> "$STATS"
        fi
        tail -"$KEEP" "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"
        tail -"$KEEPSTATS" "$STATS" > "$STATS.tmp" 2>/dev/null && mv "$STATS.tmp" "$STATS"
        sleep "$interval"
    done
}

case "$1" in
    start)
        if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
            echo "already running (pid $(cat "$PIDF"))"; exit 1
        fi
        [ -x "$BIN" ]   || { echo "missing $BIN";   exit 1; }
        [ -f "$MEDIA" ] || { echo "missing $MEDIA"; exit 1; }
        iv=${2:-120}
        loop "$iv" &
        echo $! > "$PIDF"
        echo "started (pid $(cat "$PIDF")), every ${iv}s, log $LOG"
        ;;
    stop)
        if [ -f "$PIDF" ]; then
            kill "$(cat "$PIDF")" 2>/dev/null
            rm -f "$PIDF"
            echo "loop stopped"
        else
            echo "loop was not running"
        fi
        # the backgrounded sleep/captioncast may outlive the loop shell
        killall captioncast 2>/dev/null
        kill $(pidof captioncast 2>/dev/null) 2>/dev/null
        "$BIN" --tv "$TV" --stop 2>/dev/null      # leave the TV clean
        ;;
    status)
        if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
            echo "running (pid $(cat "$PIDF"))"
        else
            echo "not running"
        fi
        [ -f "$STATS" ] && { echo "--- last runs ---"; tail -12 "$STATS"; }
        ;;
    stats)
        # played vs seeked, the correlation worth watching
        [ -f "$STATS" ] || { echo "no stats yet"; exit 0; }
        echo "runs      : $(grep -c 'pos=' "$STATS")"
        echo "  played  : $(grep -c 'state=PLAYING' "$STATS")"
        echo "  seeked  : $(grep -c 'seek=yes' "$STATS")"
        echo "  played AND seeked : $(grep 'state=PLAYING' "$STATS" | grep -c 'seek=yes')"
        echo "  asleep  : $(grep -c 'asleep' "$STATS")"
        echo "--- last runs ---"; tail -12 "$STATS"
        ;;
    once)
        "$BIN" --tv "$TV" --media "$MEDIA" --nopoll
        ;;
    *)
        echo "usage: $0 {start [seconds]|stop|status|stats|once}"; exit 1;;
esac

# Persistence: /var is ramfs, so the binary, the clip and this script vanish on
# a router reboot. To survive, remount / rw, copy them under /usr/sbin, and
# append a launch line to /etc/rcS exactly as dropbear was added - and keep
# /etc/rcS at mode 755.
