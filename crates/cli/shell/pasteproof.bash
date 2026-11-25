# pasteproof bash integration. Load with:  eval "$(pasteproof init bash)"
#
# Checks each command line when you press Enter, before bash runs it.
# A pure-bash pre-filter skips the check for ordinary lines, so most Enter
# presses start no process at all. If pasteproof is missing or fails, the
# line runs normally (fail open).

# Single-quoted $ and \ in the pre-filter are literal patterns on purpose.
# shellcheck disable=SC2016,SC1003

if [[ $- == *i* && -z ${__PASTEPROOF_LOADED-} ]] && (( BASH_VERSINFO[0] >= 4 )); then
__PASTEPROOF_LOADED=1
__pasteproof_bin=${PASTEPROOF_BIN:-@PASTEPROOF_SELF@}
__pasteproof_pasted=0

__pasteproof_mark_paste() { __pasteproof_pasted=1; }

__pasteproof_check() {
  local line=$READLINE_LINE pasted=$__pasteproof_pasted
  __pasteproof_pasted=0
  [[ -n $line && -x $__pasteproof_bin ]] || return 0
  # Pre-filter: only lines that could plausibly be risky reach the binary.
  local l=${line,,}
  case $l in
    *curl*|*wget*|*fetch*|*aria2*|*://*|*base64*|*xxd*|*openssl*|*eval*|*source*|*'. '*|*'<('*|*'$('*|*'`'*|\
    *iex*|*irm*|*iwr*|*invoke-*|*powershell*|*pwsh*|*-enc*|*mshta*|*rundll32*|*regsvr32*|\
    *certutil*|*bitsadmin*|*conhost*|*finger*|*nslookup*|*cmd*|*python*|*perl*|*ruby*|*node*|*php*|\
    *osascript*|*'| sh'*|*'|sh'*|*bash*|*zsh*|*crontab*|*autostart*|*systemd*|*launch*|*schtasks*|\
    *profile*|*authorized_keys*|*xattr*|*spctl*|*setenforce*|*ufw*|*mppreference*|\
    *'$ifs'*|*'${ifs}'*|*'\'[a-z]*|*nc\ *|*ncat*|*socat*|*scp*|*.ssh*|*'^'*|*'#'*) ;;
    *)
      if [[ $line != *[![:ascii:]]* && $line != *$'\n'* && $line != *'                              '* ]]; then
        return 0
      fi
      ;;
  esac
  local flag=
  (( pasted )) && flag=--pasted
  "$__pasteproof_bin" guard --shell bash $flag -- "$line" </dev/tty >/dev/tty 2>&1
  if (( $? == 10 )); then
    READLINE_LINE=''
    READLINE_POINT=0
  fi
}

# Enter -> run the check, then accept the (possibly cleared) line.
bind -x '"\C-x\C-p\C-c": __pasteproof_check'
bind '"\C-x\C-p\C-a": accept-line'
bind '"\C-m": "\C-x\C-p\C-c\C-x\C-p\C-a"'
bind '"\C-j": "\C-x\C-p\C-c\C-x\C-p\C-a"'
# Bracketed paste -> remember that the line was pasted.
bind -x '"\C-x\C-p\C-m": __pasteproof_mark_paste'
bind '"\C-x\C-p\C-b": bracketed-paste-begin'
bind '"\e[200~": "\C-x\C-p\C-m\C-x\C-p\C-b"'
elif [[ $- == *i* ]] && (( BASH_VERSINFO[0] < 4 )); then
  echo "pasteproof: bash ${BASH_VERSION%%(*} is too old (4.0+ needed). On macOS use zsh (the default shell) or 'brew install bash'. Not active in this shell." >&2
fi
