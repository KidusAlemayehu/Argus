# Argus — The Hundred-Eyed Sentinel

**Argus** is a C-based command-line guardian that watches every shell command before it runs.
It detects hidden threats — from Unicode confusables and terminal injection to unsafe `curl | bash` patterns — and blocks them in real time.

> *"Eyes that never sleep, guarding the command line."*

---

## Inspiration

Argus is inspired by the ideas behind [**sheeki03/tirith**](https://github.com/sheeki03/tirith) — an exceptional Rust-based security tool that protects terminals from Unicode, ANSI, and pipe-to-shell attacks.

The project began after reading [this tweet](https://x.com/sheeki03/status/2018382483465867444?s=20) by **@sheeki03**, which highlights how malicious domains can impersonate trusted URLs using Cyrillic or other Unicode lookalikes.

Argus re-imagines that same defense in pure C — a **lightweight, dependency-free terminal sentinel** that operates fully offline while preserving the same real-time awareness and protection.

---

## Features

| Category                             | Description                                                                                        |                  |      |
| ------------------------------------ | -------------------------------------------------------------------------------------------------- | ---------------- | ---- |
|  **Manual diff checking**          | Compare two strings or URLs byte by byte to reveal hidden differences (`argus diff <a> <b>`).      |                  |      |
|  **Unicode confusables detection** | Detect Cyrillic/Greek lookalikes (`і`, `о`, `а`) that can disguise malicious domains.              |                  |      |
|  **Real-time shell protection**    | Hooks directly into your shell (`bash`, `zsh`, `fish`) and inspects each command before execution. |                  |      |
|  **Pipe-to-shell protection**      | Warns or blocks commands like `curl ...                                                            | bash`or`wget ... | sh`. |
|  **Insecure transport detection**  | Blocks HTTP-based scripts and insecure downloads.                                                  |                  |      |
|  **Cross-shell support**          | Works seamlessly in Bash, Zsh, and Fish.                                                           |                  |      |

---

## Installation

### Build from source

```bash
git clone https://github.com/KidusAlemayehu/argus.git
cd argus
make
```

Optionally install globally:

```bash
sudo cp argus /usr/local/bin/
```

---

## Activation

Add Argus to your shell startup file.

### Bash

```bash
eval "$(argus init --shell bash)"
```

### Zsh

```bash
eval "$(argus init --shell zsh)"
```

### Fish

```bash
argus init --shell fish | source
```

Now Argus will automatically inspect each command before execution.

---

## Usage

### Compare strings (diff mode)

```bash
argus diff "curl https://install.example-cli" "curl https://іnstall.example-clі"
```

Output:

```
position 12: 'i' (0x69) vs 'і' (0xd1 0x96)
argus: BLOCKED — potential homograph / confusable attack
```

### Real-time shell protection

Once active, Argus monitors all commands:

```bash
$ curl -sSL https://get.docker.com | bash
argus: WARNING — pipe-to-shell detected ("curl -sSL https://get.docker.com | bash")
```

Blocked command:

```bash
$ curl http://example.com | sh
argus: BLOCKED — insecure http transport
```

Safe commands:

```bash
$ git status
$ ls -la
```

---

## How It Works

* **Hooks into your shell** using preexec or DEBUG traps.
* **Analyzes each command** before execution.
* **Inspects Unicode characters** for confusables (Cyrillic, Greek).
* **Warns or blocks** based on severity.

Everything runs **locally** — no network calls, no telemetry, no background daemons.

---

## Example Commands

| Command                      | Description                           |        |                                          |
| ---------------------------- | ------------------------------------- | ------ | ---------------------------------------- |
| `argus diff <a> <b>`         | Manual byte-level comparison.         |        |                                          |
| `argus check -- "<command>"` | Analyze a command without running it. |        |                                          |
| `argus init --shell <bash    | zsh                                   | fish>` | Print activation snippet for your shell. |

---

## Next Roadmap

| Step | Feature                           | Status |
| ---- | --------------------------------- | ------ |
| 1    | Manual diff checking              | Done      |
| 2    | Real-time shell protection        | Done      |
| 3    | Unicode confusables detection     | Done      |
| 4    | ANSI / Zero-width / Bidi analysis | In Progress      |
| 5    | Policy-based blocking (YAML)      | Not Done     |
| 6    | Cross-platform integration        | Not Done     |

---

## License

MIT License
2026 Argus

---
