# GitHub MCP core

This document describes the standalone GitHub MCP core: the server, the client, publication approval, and the background publisher.

It does not describe the spoken ICY voice application. That application remains in the ICY workspace. Its entry point, voice engine, browser tools, and audio path are not part of this package and are not required to run the server.

This core is not zero-configuration. A live call needs a local policy file, the Python packages below, and a Windows credential. The example policy shipped beside this document is not loaded automatically.

## Architecture

```
caller → GithubMcpClient → stdio → mcp_servers.github_server → GitHub REST API
                ↑
     BackgroundGithubPublisher on icy-background-task
```

The server process is `mcp_servers.github_server`. The client, approval logic, and publisher live in the `realtime_c` package. The server imports `realtime_c.github_approval` and `realtime_c.redaction` when a tool runs. Both packages must be importable from the repository root.

Registered server tools:

| Tool | Effect |
|---|---|
| `github_get_repository` | One read of an allowlisted repository |
| `github_create_repository` | Creates one empty public repository when a create grant allows it |
| `github_create_file` | Publishes one approved file |
| `github_commit_files` | Publishes the approved files, one request per file |

The server does not register `github_get_job_status`. On an enabled read-only policy, the only model-visible GitHub tool name is `github_get_repository`. Write tools stay off that list. The spoken application has separate prepare and approve tools. Those tools are part of the ICY workspace, not of this core package.

## Install

From the repository root, with Python 3.11 or a compatible 3.x interpreter:

```
python -m pip install -r requirements.txt
```

The core imports `mcp` and `httpx`. `requirements.txt` declares:

- `mcp>=2.3,<3`
- `httpx>=0.27,<1`

It also declares `certifi`, `openai`, and `geonamescache`. This core does not import `openai` or `geonamescache`. Installing the file as written is reproducible and also installs those unused packages.

`mcp` 2.3 installs `anyio` and `mcp-types`. `httpx` installs `certifi`, `httpcore`, and `idna`. On Windows, `mcp` also depends on `pywin32`. Do not edit the version bounds in this package to chase another environment.

## Server startup

From the repository root:

```
python -m mcp_servers.github_server
```

The process speaks MCP over stdio. Startup arms a lazy HTTP client, checks whether a Windows credential is present, and logs `auth=ok` or `auth=missing`. The log does not contain the credential. The process then serves stdio until it exits, and closes the HTTP client on the way out.

Policy is read from `config/github_mcp.json` under `GITHUB_MCP_ROOT`, or under the current working directory when that variable is unset. A missing or malformed file fails closed. `enabled: false` keeps every GitHub tool closed even if this process is running.

`config/github_mcp.example.json` is documentation only. The loader never opens that filename. Copying it onto `config/github_mcp.json` is a separate operator action. The example stays disabled, so a copy still refuses reads and writes until someone edits the copy.

## Authentication

On Windows, the server reads one Windows Credential Manager entry. It accepts the blob only when all of the metadata matches:

- Target name: `me3-icy-github-mcp-token`
- Username: `github-token`
- Type: generic (`CRED_TYPE_GENERIC`, value 1)
- Persist: local machine (`CRED_PERSIST_LOCAL_MACHINE`, value 2)

The blob must be a classic `ghp_` token or a fine-grained `github_pat_` token. The server checks the shape and then uses the value as a bearer token. It does not log the value.

There is no environment fallback and no file fallback. `GITHUB_TOKEN`, `GITHUB_MCP_TOKEN`, `GH_TOKEN`, and `GITHUB_GRANT_HMAC_KEY` are removed from the child environment. Setting them does not authenticate the server. A file named `.env.github` is not read.

The client still places the name `GITHUB_MCP_SECRET_FILE` in the child environment. That name is not a credential source. Creating a secret file does not enable GitHub access.

The parent process does not need the token to start the client. The child reads it only inside the server process, and only when a tool builds request headers.

Linux does not use Credential Manager. `realtime_c.github_credentials` selects Freedesktop Secret Service through `secret-tool` when that program is installed, and an unavailable-backend result when it is not. The Linux backend stays empty until `python -m realtime_c.github_credentials` stores a credential from a hidden prompt. Retrieval, replacement, and deletion go through that same provider. Status output names the backend and whether a credential is configured. It does not include the credential. A missing `secret-tool` does not fall back to a file or an environment variable.

## Policy

Boolean flags, all defaulting to false when omitted:

- `allow_reads`
- `allow_writes`
- `allow_repo_creation`
- `allow_workflows`
- `allow_permissions`
- `allow_destructive`

`enabled` defaults to false when omitted. `allowed_owner` is one GitHub user or organization name. `allowed_repos` is a list of repository names. `*` is rejected. A symlink in place of the policy file is rejected.

A safe disabled starting point is `config/github_mcp.example.json`: reads requested, writes off, repository creation off, and the other three flags off. The owner and repository in that file are the literal examples `example-owner` and `example-repository`. They are not an account and not an allowlist entry for a real repository.

The ICY workspace keeps its own `config/github_mcp.json`. That file is the live policy. It is not part of this package. Shipping this core does not change it.

Tool gates:

- `enabled` false returns `github_mcp_disabled`.
- A read without `allow_reads` returns `github_reads_disabled`.
- A write without `allow_writes` returns `github_writes_disabled`.
- Repository creation also requires `allow_repo_creation`, or the tool returns `github_repo_creation_disabled`.

Reads require the owner to match `allowed_owner` without regard to case, and the repository name to appear in `allowed_repos`. An empty list returns `no_allowed_repos_configured`. A name that is not listed returns `repo_not_allowlisted`. Creating a repository does not add the new name to `allowed_repos`. A later read of that name still fails until the operator lists it.

Workflow, permission, and destructive flags stay false in the example. This core does not grant those operations by default.

## Publication approval

Publication uses two one-shot in-memory grants. Preparing a preview does not contact GitHub and does not change `allowed_repos`.

1. `prepare_publication_authorization` records the owner, public visibility, description, branch, and the path plus SHA-256 of each file.
2. The preview waits in `awaiting_approval`.
3. One confirmation accepts the preview and mints two ids: a create grant and a sibling content grant. They share the fingerprint, the file hashes, and the expiry.
4. The server consumes each grant once. A second confirmation returns `confirmation_replayed`. A consumed grant returns `approval_consumed`.

Confirmation requires `enabled`, `allow_writes`, and `allow_repo_creation`. The owner must match `allowed_owner`. Visibility must be the string `public`. A changed repository name, description, branch, path list, or file hash leaves the grant untouched.

Grants expire 300 seconds after they are prepared (`PUBLICATION_TTL_S`). Expiry is `now >= expires_at`. Restarting the process drops every grant. Nothing in this flow is stored as a GitHub credential.

An accepted grant may name a repository that is not yet in `allowed_repos`. That grant can pass the publication allowlist check for its own create or content call. It still requires the same owner. It does not rewrite the policy file.

## Background worker and session ownership

`BackgroundTaskWorker` runs on the thread named `icy-background-task`. The publisher binds the MCP client to that worker. A write tool call from any other thread returns `direct_write_decision` and does not enter the session.

The client loop runs on `github-mcp-worker`. That thread owns the stdio session and the server child. The default child command is the current Python interpreter with `-m mcp_servers.github_server`, using the repository root as its working directory. The child receives `GITHUB_MCP_ROOT` and a small environment allowlist. Parent API keys and GitHub token variables are not copied.

Disabled policy does not start the client thread, the event loop, or the child.

Shutdown stops the worker first. The client is closed only when the worker thread is no longer alive. `close()` asks the client loop to stop and joins the client thread for up to 3.5 seconds. Stream close and child termination run in the session cleanup on that loop. The caller does not create a separate shutdown coroutine. A second `close()` is safe.

## Repository creation

`github_create_repository` consumes the create grant, then:

1. Looks up the authenticated user and the repository.
2. Treats HTTP 404 as "absent".
3. Sends one `POST https://api.github.com/user/repos` with `private: false` and `auto_init: false`.
4. Requires the resulting repository to match the owner login, the requested name, public visibility, the approved description, and size 0.

Only public repositories can be created. A private request is rejected before any POST. A repository that already exists and does not match this binding returns `unrelated_repository_exists` and is not adopted.

If the POST times out, the server verifies with GET and does not send a second POST. An inconclusive verification fails closed and leaves the outcome uncertain.

## File publication and verification

`github_commit_files` consumes the content grant and uploads files in sorted path order. Each file is its own `PUT` to the Contents API. The commit message is `Publish approved files`. When the grant contains more than one file, the message is that text plus the path.

HTTP 200 or 201 from the PUT is not success. The server then `GET`s the contents for the approved branch, decodes the payload, and compares SHA-256 with the grant. A mismatch stops the batch. The remaining files are not uploaded. The report keeps any commit SHA GitHub already returned for the mismatched file and does not retry the PUT.

An empty file is valid. HTTP 409 or 422 is a conflict: no verification GET and no retry. A timeout after PUT performs one recovery GET and does not repeat the PUT. When that GET matches the grant hash, the recorded SHA is the contents SHA from the GET.

A directory scan used by the publisher accepts `.md`, `.txt`, `.py`, `.json`, `.toml`, `.yml`, `.yaml`, and `.rst`. It skips `.git`, virtual environments, caches, and build directories. It skips paths and text that look like secrets, including `.env` names and private-key blocks. The scan is a heuristic. Files larger than 100,000 bytes are excluded. That per-file cap is fixed. This package does not raise it.

A multi-file publication is not atomic. Some files can be verified while a later file fails or stays uncertain.

## Cancellation and shutdown

Cancellation is checked before a grant is consumed and before each file. Cancelling before dispatch does not create a repository and does not upload. Cancelling during creation does not start file publication and does not repeat the POST. Cancelling during a PUT does not repeat that PUT.

Uncertain create or upload results stay uncertain. The publisher does not treat them as success and does not clear the possibility that the remote operation finished.

## Limitations

- Grants live in process memory and disappear on restart.
- Repository creation supports public repositories only.
- A new repository name is not added to the read allowlist.
- The size-0 check on a new repository is a heuristic.
- Secret detection is incomplete.
- An abandoned uncertain create can leave an empty public repository. Cleanup is manual.
- The HTTP client is created only when a publication is admitted. Tests must not call `main()`.
- This package does not start the spoken ICY agent or open a microphone.
- The Pi credential command does not create a token and does not change GitHub token scopes.

## ICY voice capabilities

The spoken assistant stays the existing ICY pipeline. GitHub tools are added to the same MCP session when `config/github_mcp.json` has `enabled` and `allow_reads`. The production file stays disabled. Enabling reads does not enable writes.

Read tools, all GET-only and allowlisted:

- Repository details, repository list, branches, and tags.
- Directory listing, file text, commits, one commit, and compare.
- Issues, pull requests, pull request comments, and review states.
- Releases.
- Workflow files, runs, and a log-availability check. Those three stay closed unless `allow_workflows` is true. Collaborator listing stays closed unless `allow_permissions` is true. The log archive is not downloaded.

Examples: "Show me my GitHub repositories." "Open the README." "Show the latest commits." "Check whether there are open pull requests."

Local Git uses `config/git_workspace.json` with `workspace_root`. Paths outside that directory are rejected. Clone will not replace an existing directory. Pull and push stop when the worktree is dirty. Remote URLs that contain credentials are rejected, and other remote URLs are redacted. There is no automatic clean or reset.

Examples: "Clone that repository into my approved workspace." "Check my local changes."

Writes use `github_prepare_operation` and `github_approve_operation`. The preview is bound to the operation, target, and content hash. Approval is one-shot, expires, and is recorded in `realtime_c/logs/github_operations/consumed.ledger`. That ledger is separate from publication replay. A changed preview is refused. The remote result is read back after a successful response. `allow_writes` stays false in the committed production policy. Repository-creation grants are not reused.

GitHub reads, clone, fetch, pull, and approved writes return a `task_id` when the background worker is attached. A later turn uses `icy_task_status`, `icy_task_result`, and `icy_task_cancel`. The worker does not speak and does not edit conversation history. Clone, fetch, and pull use a 75 second worker deadline. An approved write uses 90 seconds. Those deadlines do not kill a Git process or a GitHub request that has already started. Cancellation before the worker starts does not run the operation. Cancellation after it starts reports that the operation may still be running.

Short workspace reads stay on the caller: status, branch, remotes, log, diff, changed files, and a clean check. A second mutating Git command returns `workspace_busy` while one mutation holds the workspace lock.

The existing 16 local MCP tools stay registered. GitHub names are additional. Production policy keeps write, workflow, permission, and destructive tools hidden.

## Raspberry Pi 5

SSH to `xelaubalde@192.168.100.12` succeeded on 2026-11-27. The machine is aarch64, Python 3.13.5, Git 2.47.3, 4 cores, and about 4 GB of RAM with about 3.6 GB available. `/home/xelaubalde/me3/.venv` imports `mcp` and `httpx`. Its `config/github_mcp.json` has `enabled` false. `secret-tool` is not installed, gnome-keyring is inactive, and `sudo` asks for a password, so packages were not installed from this session. The spoken assistant was not started. No microphone or speaker was used. The Windows credential was not copied to the Pi.

Install from a checkout. GitHub stays disabled until the policy file is edited on purpose:

```
python3 -m pip install -r requirements.txt
sudo apt-get install -y git libsecret-tools
python3 -m realtime_c.github_credentials
```

The credential command prompts twice without echoing, stores the value through Secret Service, and prints only whether it was stored. Do not pass the value on the command line.

Copy `config/github_mcp.example.json` only as a starting point, then keep `enabled` false until a read-only trial. Keep `allow_writes`, `allow_repo_creation`, `allow_workflows`, `allow_permissions`, and `allow_destructive` false. Copy `config/git_workspace.example.json` to `config/git_workspace.json` and set `workspace_root` to an existing directory. Do not point that directory at the assistant checkout.

Health, from the repository root:

```
python3 -c "from realtime_c.github_credentials import sanitized_status; print(sanitized_status())"
python3 -m mcp_servers.github_server
```

The status line has no credential. The server logs `auth=ok` or `auth=missing` and then waits on stdio. Stop it with an end-of-file on stdin. Stop the background worker before closing an MCP child. If a Git command is still inside the worker, shutdown does not claim that command was killed.

If Secret Service is missing, status returns `unavailable_backend` and GitHub requests stay unauthenticated. Do not add a token file, a shell profile, or an environment variable to bypass that.
