# pasteproof zsh integration. Load with:  eval "$(pasteproof init zsh)"
#
# Wraps the accept-line widget (Enter) and the bracketed-paste widget.
# A pure-zsh pre-filter skips the check for ordinary lines. If pasteproof
# is missing or fails, the line runs normally (fail open).

if [[ -o interactive && -z ${__PASTEPROOF_LOADED-} ]]; then
typeset -g __PASTEPROOF_LOADED=1
typeset -g __pasteproof_pasted=0
typeset -g __pasteproof_bin=${PASTEPROOF_BIN:-@PASTEPROOF_SELF@}

__pasteproof_bracketed_paste() {
  __pasteproof_pasted=1
  zle .bracketed-paste "$@"
}
zle -N bracketed-paste __pasteproof_bracketed_paste

__pasteproof_accept_line() {
  emulate -L zsh
  local line=$BUFFER pasted=$__pasteproof_pasted
  __pasteproof_pasted=0
  if [[ -n $line && -x $__pasteproof_bin ]]; then
    local l=${(L)line}
    if [[ $l == *(curl|wget|fetch|aria2|://|base64|xxd|openssl|eval|source|'<('|'$('|'`'|iex|irm|iwr|invoke-|powershell|pwsh|-enc|mshta|rundll32|regsvr32|msiexec|certutil|bitsadmin|conhost|finger|nslookup|cmd|python|perl|ruby|node|php|osascript|'| sh'|'|sh'|bash|zsh|crontab|autostart|systemd|launch|schtasks|bashrc|zshrc|profile|authorized_keys|xattr|spctl|setenforce|ufw|mppreference|'$ifs'|'${ifs}'|'\x'|ncat|socat|scp|.ssh|'^'|'#')* \
       || $line == *[^\ -~]* || $line == *'                              '* ]]; then
      local -a flag
      (( pasted )) && flag=(--pasted)
      zle -I
      "$__pasteproof_bin" guard --shell zsh $flag -- "$line" </dev/tty >/dev/tty 2>&1
      if (( $? == 10 )); then
        BUFFER=''
        zle .reset-prompt
        return 0
      fi
    fi
  fi
  zle .accept-line
}
zle -N accept-line __pasteproof_accept_line
fi
