# Shared by scripts/deploy.sh and scripts/letsencrypt.sh: the ONE DNS-name grammar a hostname must
# pass BEFORE it is placed in a remote shell command (mirrors src/App/Tls/DnsName.php exactly):
# lowercase LDH labels of 1-63 chars, dot-separated, at most 253 chars. No newline, quote, slash,
# comma, space, wildcard or shell metacharacter can pass, so a value that reaches `ssh` can never
# open a new command or a new nginx directive. POSIX sh; sourced, not executed.

funnypot_dns_name_valid() {
    _fp_n="$1"
    [ -n "$_fp_n" ] || return 1
    [ "${#_fp_n}" -le 253 ] || return 1
    # grep matches line by line, so a value with an embedded line break would pass on its first
    # line alone: refuse any CR/LF outright before the grammar check.
    _fp_nl="$(printf '\nx')"; _fp_nl="${_fp_nl%x}"
    _fp_cr="$(printf '\rx')"; _fp_cr="${_fp_cr%x}"
    case "$_fp_n" in
        *"$_fp_nl"*|*"$_fp_cr"*) return 1 ;;
    esac
    printf '%s' "$_fp_n" | grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
}

# Fail the calling script (exit 1) unless $2 is empty or a valid DNS name. $1 names the variable
# for the error message; the rejected value is never echoed.
funnypot_require_dns_name_or_empty() {
    _fp_var="$1"
    _fp_val="$2"
    if [ -n "$_fp_val" ] && ! funnypot_dns_name_valid "$_fp_val"; then
        echo "error: $_fp_var is not a valid lowercase DNS name (letters/digits/hyphens, dot-separated) — refusing to build any remote command with it." >&2
        exit 1
    fi
}
