/*
   Webshell / backdoor markers for the lin_yara triage scan.
   High-signal only: a request superglobal (or an obfuscation wrapper) flowing
   straight into an exec sink -- frameworks use eval/system/base64, but almost
   never with $_GET/$_POST as the direct argument. Triage signal, not a verdict.
*/

rule webshell_php_input_to_exec
{
    meta:
        author = "artifact-engine"
        description = "PHP exec sink fed directly from a request superglobal or obfuscator"
    strings:
        $a = /(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE|SERVER)/ nocase
        $b = /(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(/ nocase
    condition:
        any of them
}

rule webshell_php_dynamic_call
{
    meta:
        description = "Dynamic call with a request superglobal as the function name"
    strings:
        $a = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{0,40}\]\s*\(/
    condition:
        $a
}

rule webshell_php_preg_replace_e
{
    meta:
        description = "preg_replace with the /e modifier (code execution)"
    strings:
        $a = /preg_replace\s*\(\s*['"][^'"]*\/[a-z]*e[a-z]*['"]/ nocase
    condition:
        $a
}

rule webshell_known_family
{
    meta:
        description = "Known PHP webshell family markers (specific names only)"
    strings:
        $a = "c99shell" nocase
        $b = "r57shell" nocase
        $c = "b374k" nocase
        $d = "China Chopper" nocase
        $e = "antSword" nocase
        $f = "weevely" nocase
    condition:
        any of them
}

rule webshell_jsp_exec
{
    meta:
        description = "JSP that runs OS commands from a request parameter"
    strings:
        $req = "request.getParameter"
        $a = "Runtime.getRuntime().exec"
        $b = "ProcessBuilder"
    condition:
        $req and ($a or $b)
}

rule webshell_asp_eval_request
{
    meta:
        description = "Classic ASP eval/execute of request input (requires an ASP tag)"
    strings:
        $tag = "<%"
        $a = /(eval|execute)\s*\(\s*request/ nocase
        $b = "WScript.Shell" nocase
    condition:
        $tag and ($a or $b)
}
