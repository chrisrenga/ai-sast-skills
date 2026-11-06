# Building the sandbox

Run control needs two layers of isolation. This file describes one way to build each with
widely available tools. A department's platform team may have a better one; what matters is
that every control below is enforced, not how.

## Layer 1: where the agent runs

The agent client reads the scan copy and talks to the model. It never runs target code
itself.

- A dedicated virtual machine or container, rebuilt for each assessment or reset to a clean
  image.
- No personal or service credentials: no cloud sessions, single sign-on cookies, SSH keys or
  agents, Git credentials, package registry tokens, or container-engine socket.
- Network egress only to the approved model route, enforced by the network (an egress proxy
  or firewall allowlist), not by the agent's settings.
- Agent-client telemetry, tracing and prompt-sharing features turned off.
- Mounted: the scan copy (read-only), the skills (read-only), and the output directory.

## Layer 2: where target code runs

Only when the run scope says `execution: sandboxed-local`. Cloudflare's method lists the
controls (`cloudflare/METHOD.md`, Universal execution safety). With a rootless container
engine (Docker rootless or Podman), one check looks like this:

```sh
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 65534:65534 \
  --cpus 1 --memory 1g --memory-swap 1g --pids-limit 256 \
  --ulimit fsize=104857600 --ulimit nofile=1024:1024 \
  --tmpfs /tmp:rw,size=64m \
  --mount type=bind,src="$SCAN_COPY",dst=/src,readonly \
  --mount type=bind,src="$AGENT_SCRATCH",dst=/scratch \
  --env HOME=/scratch/home --env TMPDIR=/scratch/tmp --env CI=1 \
  --workdir /scratch/work \
  "$TOOLCHAIN_IMAGE" \
  timeout --kill-after=10 300 <test command>
```

| Control | How this meets it |
|---|---|
| No external network | `--network none` leaves only the container's own loopback, which upstream allows for a local client and server. |
| Empty, allowlisted environment | Nothing from the host environment is passed; only the listed variables are set. |
| Read-only target and toolchain | `--read-only` root filesystem and a read-only bind of the scan copy. |
| Writes only to scratch | The agent's own scratch directory is the only writable mount, apart from a small `/tmp`. |
| CPU, memory, processes, file size | `--cpus`, `--memory`, `--pids-limit`, `--ulimit fsize` (bytes). |
| Disk | `fsize` caps each file. For a total cap, put each agent's scratch on a small dedicated filesystem, for example a fixed-size loop-mounted image or a quota-limited directory. |
| Wall clock | `timeout` inside the container, plus a host-side watchdog that runs `docker kill` if the container outlives it. |

If the build must write beside the source, the agent copies the source into
`/scratch/work` first, as upstream allows.

### Dependencies

The run never fetches dependencies. Either the toolchain image already has them, or the check
cannot run and the candidate stays `needs_validation` with that blocker. If the department
allows it, a platform engineer can build a dependency image from the target's lockfile before
the run, in a separate step with network access. Record that image's digest in
`run-record.json` under `scope.sandbox`.

### Evidence

Most decisive evidence is the test runner's output. Capture it on the host from the
container's standard output and error, with a size limit, and have the parent write it into
the verifier's `artifacts/` directory. Trusted code wrote that file, so it needs no promotion.
Files that target code wrote in scratch need Cloudflare's promotion procedure
(`cloudflare/METHOD.md`, Write isolation). It needs directory-relative, no-follow file
operations. If your tooling cannot do them, do not use those files as evidence: the candidate
keeps `needs_validation` with the promotion blocker.

### What never goes in

The container-engine socket, the host home directory, SSH or GPG agents, cloud credential
files, real data, and any other agent's scratch or artifacts.
