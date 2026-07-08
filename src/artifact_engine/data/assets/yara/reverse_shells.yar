/*
   Reverse-shell / one-liner backdoor patterns for the lin_yara triage scan.
   These are the canonical interactive-shell-over-socket idioms; benign scripts
   rarely combine an interactive shell with a raw socket redirection.
*/

rule revshell_dev_tcp
{
    meta:
        author = "artifact-engine"
        description = "Interactive shell redirected over /dev/tcp or /dev/udp"
    strings:
        $tcp = "/dev/tcp/"
        $udp = "/dev/udp/"
        $i = /(ba)?sh\s+-i\b/
    condition:
        ($tcp or $udp) and $i
}

rule revshell_nc_mkfifo
{
    meta:
        description = "netcat -e / mkfifo back-pipe reverse shell"
    strings:
        $a = /n(c|cat)\s+(-[a-zA-Z]*\s+)*-e\s+\/bin\/(ba)?sh/ nocase
        $b = /mkfifo\s+\/tmp\/[^\s;]+;\s*(cat|nc)/
        $c = "rm -f /tmp/f;mkfifo /tmp/f"
    condition:
        any of them
}

rule revshell_python
{
    meta:
        description = "Python socket reverse shell (pty.spawn, or dup2 onto a shell)"
    strings:
        $sock = "socket.socket"
        $pty = "pty.spawn"
        $dup = "os.dup2"
        $sh = /["']\/bin\/(ba)?sh["']/
    condition:
        $sock and ($pty or ($dup and $sh))
}

rule revshell_perl_ruby
{
    meta:
        description = "Perl/Ruby inline socket reverse shell"
    strings:
        $perl = /perl\s+-e\s+['"].{0,40}(socket|Socket)/ nocase
        $ruby = /ruby\s+-rsocket/ nocase
        $exec = /exec\s*\(?["']\/bin\/(ba)?sh/
    condition:
        ($perl or $ruby) and $exec
}
