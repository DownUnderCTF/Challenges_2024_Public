# fix for screen readers
if grep -Fqa 'accessibility=' /proc/cmdline; then
    setopt SINGLE_LINE_ZLE
fi

~/.automated_script.sh
