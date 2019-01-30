#!/bin/bash
groups
bins=("apt-get" "apt" "aria2c" "ash" "awk" "base64" "bash" "busybox" "cat" "chmod" "chown" "cp" "cpulimit" "crontab" "csh" "curl" "cut" "dash" "date" "dd" "diff" "docker" "easy_install" "ed" "emacs" "env" "expand" "expect" "facter" "find" "finger" "flock" "fmt" "fold" "ftp" "gdb" "git" "grep" "head" "ionice" "jjs" "journalctl" "jq" "jrunscript" "ksh" "ld.so" "less" "ltrace" "lua" "mail" "make" "man" "more" "mount" "mv" "mysql" "nano" "nc" "nice" "nl" "nmap" "node" "od" "perl" "pg" "php" "pico" "pip" "puppet" "python" "red" "rlwrap" "rpm" "rpmquery" "rsync" "ruby" "scp" "sed" "setarch" "sftp" "shuf" "smbclient" "socat" "sort" "sqlite3" "ssh" "stdbuf" "strace" "tail" "tar" "taskset" "tclsh" "tcpdump" "tee" "telnet" "tftp" "time" "timeout" "ul" "unexpand" "uniq" "unshare" "vi" "vim" "watch" "wget" "whois" "wish" "xargs" "xxd" "zip" "zsh")
for i in "${bins[@]}"
do
  if which $i > /dev/null; then
    ls -lah $(which $i)
  fi
done
