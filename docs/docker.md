# Running the MCP server in Docker

`Dockerfile.mcp` builds an image with clang 19, clang-tidy 19, cppcheck, Semgrep 1.186.0 and
cert-review. Infer and CodeQL are not included; [analyzers.md](analyzers.md) shows how to add
Infer in a derived image (amd64 only).
Its entrypoint is `cert-review-mcp`, the MCP server over stdio; the `cert-review` CLI is in
the same image. `./Dockerfile` is a different image: the GitHub Action.

Release tags publish multi-arch images (linux/amd64, linux/arm64) to Docker Hub as
`raminnietzsche/cert-review-mcp:<version>` and `:latest`
([workflow](../.github/workflows/docker-publish.yml)). To build locally instead:

```bash
docker build -f Dockerfile.mcp -t cert-review-mcp .
# multi-arch, pushed to a registry:
docker buildx build -f Dockerfile.mcp --platform linux/amd64,linux/arm64 -t <user>/cert-review-mcp:<version> --push .
```

## Paths: mount the project at the same path

The tools take absolute paths chosen by the client, which knows host paths. Mount the
project at the **same absolute path** inside the container, so `/home/me/proj/src/a.c` means
the same file on both sides:

```bash
docker run -i --rm -v /home/me/proj:/home/me/proj:ro cert-review-mcp
```

`:ro` is enough: the tools never write. A `compile_commands.json` must also be visible at the
path it names, and its include paths must exist in the container. A compilation database made
on macOS will not work in this Linux image; generate one on Linux or in a container.

## MCP client configuration

Claude Desktop (`claude_desktop_config.json`), Cursor (`.cursor/mcp.json`) and other clients
that start stdio servers from a command:

```json
{
  "mcpServers": {
    "cert-review": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
               "-v", "/home/me/proj:/home/me/proj:ro",
               "cert-review-mcp"]
    }
  }
}
```

Replace `cert-review-mcp` with `raminnietzsche/cert-review-mcp:latest` (or a version tag) to use the
published image. Claude Code:

```bash
claude mcp add cert-review -- docker run -i --rm -v "$PWD:$PWD:ro" cert-review-mcp
```

Keep `-i` (stdio needs it) and do not add `-t` (a TTY corrupts the JSON-RPC stream).

## CLI from the same image

The image **ENTRYPOINT** is `cert-review-mcp`. For the CLI, override the entrypoint:

```bash
docker run --rm -v "$PWD:$PWD" -w "$PWD" --entrypoint cert-review cert-review-mcp \
  diff --repo "$PWD" --base origin/main --format markdown
```

Draft a full PR comment (static + packet hints, same as MCP `review_pr`):

```bash
docker run --rm -v "$PWD:$PWD" -w "$PWD" --entrypoint cert-review raminnietzsche/cert-review-mcp:latest \
  review-pr --repo "$PWD" --base origin/main --profile ceph \
  --github-footer mcp -o /tmp/cert-comment.md
```

GitHub Actions on a fork: see [action.md](action.md#pr-comment-on-pull_request_target-fork-mirrors) and
`ci/github/pr-cert-review-mcp.yml`.

## Check that it works

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"chk","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | docker run -i --rm cert-review-mcp | tail -1 | jq '.result.tools[].name'
```

It should list 10 tools.

## Glama

The [Glama](https://glama.ai/mcp/servers) registry builds `Dockerfile.mcp` and introspects the
server. `glama.json` at the repository root names the maintainer.
