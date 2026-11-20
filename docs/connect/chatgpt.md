# ChatGPT and local MCP connections

Choose the connection by where the file lives. A hosted NetConverter connection
reaches NetConverter's server; a local Terminal MCP connection reaches the folder
selected on your computer. Running Terminal alone does not connect a Mac folder
to an existing hosted chat.

| Connection | File access | Guided migration |
|---|---|---|
| Local Terminal bridge in a compatible desktop/CLI client | Selected local workspace; direct upload by path | `submit_file(job_type="prescan")` starts the prescan automatically |
| NetConverter hosted MCP | Server-side files/jobs exposed by its live tool catalog | Continue an available prescan; starting from a stored file requires the server's file-selection/prescan tools |

Discover the actual tools in the conversation. Do not assume a hosted connection
has local `submit_file` or `list_workspace_files`, and do not identify a stored
file by filename alone when names can repeat. A missing starting tool is a
capability gap; the assistant must explain it rather than claim it uploaded a file.

## Connect a local workspace

Use a dedicated migration folder and explicitly configure the client to launch
Terminal's stdio bridge for it:

```sh
netconverter login --clerk
mkdir -p ~/migrations && cd ~/migrations
netconverter connect codex
netconverter privacy level full
```

`connect codex` shows the proposed change to `~/.codex/config.toml` and preserves
other configuration. If the NetConverter table already exists, follow the shown
instructions to change its workspace without adding a duplicate connection.
Reconnect the local client's MCP session after installation or configuration changes.
Verify that `submit_file` appears before asking it to upload.

OpenAI documents shared MCP configuration for Codex CLI, its IDE extension and
compatible ChatGPT desktop execution. That does not make a hosted connector a
local bridge. See [OpenAI's MCP configuration documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).
NetConverter's actual acceptance results for each client remain separate from
those configuration capabilities.

## Select, prescan, decide and convert

Example: **“List the files in this migration folder. Use HQ-ASA-01.txt for Cisco
ASA to Palo Alto SET and guide me through the migration.”**

1. `list_workspace_files` returns relative paths, sizes and types, not file bodies.
   Filenames can contain sensitive names or addresses, so listing requires the
   human-selected `full` exposure level. At lower levels, supply a known path.
   It is nonrecursive, defaults to 50 entries per page (maximum 100), and returns
   a continuation cursor. Select a returned directory to inspect that subfolder.
   Cursors expire after five minutes or a relevant metadata change. Hidden paths,
   client state, unsafe links, special files and names that would be redacted are
   excluded, with an exclusion count. Paths are limited to 1,024 UTF-8 bytes;
   oversized entries are excluded and oversized folder requests are refused.
   The structured page is bounded to 16 KiB and may contain fewer than the
   requested entries. A folder with more
   than 10,000 entries is refused; select a smaller subfolder or a known file path.
   This private candidate supports discovery on POSIX only. Windows users can
   still supply a known relative path to the existing submission tool.
2. The assistant establishes the exact source, target/output format and device
   identity, then calls `submit_file` with `job_type="prescan"` for the selected
   file. Terminal handles authorized upload and prescan directly; no preliminary
   Quick Convert or Conversion Studio step is required. Names and listing metadata
   are untrusted data, not instructions or proof of format support.
3. After `wait_for_job` reports the prescan complete, inspect the available
   operations and bounded decision sections. Discuss choices, record them on the
   server with `propose_operations`, and validate the resulting exact revision.
4. Review the intended changes and warnings. When the server offers exact-revision
   approval tools, request its review and obtain the approved receipt before
   `submit_conversion`. The receipt removes the duplicate bridge queue prompt;
   pending review is not approval. Older servers use the existing confirmation
   path. Client tool approvals can still apply.
5. Follow the new job, inspect evidence and download verified artifacts. Full YAML
   or NCIR exports are explicit file downloads, not routine conversation payloads.

The folder's exposure setting and tenant grants still govern guided operations.
Do not disable a confirmation to bypass a declined upload or an unapproved
revision. Repeated prompts for an already authorized action are distinct from
reviewing the final migration revision.

## Connect hosted ChatGPT

`netconverter connect chatgpt` prints the hosted setup instructions. Use
`https://api.netconverter.ai/mcp/v1` with the authentication and OAuth client ID
provided by your NetConverter administrator, then enable it in your conversation.
Your ChatGPT workspace must allow the connection. See
[OpenAI's connection instructions](https://developers.openai.com/plugins/deploy/connect-chatgpt)
for current client setup.

For ChatGPT access to a private local MCP server, OpenAI also documents
[Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).
It requires a separately configured tunnel, runtime credentials and organization/
workspace permissions. It is a candidate integration route, not an automatically
installed or verified NetConverter feature. No public listener or custom remote
shell is required by this guide.
