# Baseline-only smoke; run against the pre-fix runner_runtime.py, then discard.
import os
import select
import subprocess
import tempfile
import time
from dataclasses import replace
from tools.release_verify import runner_runtime

runtime_token = "synthetic-runtime-token-baseline-probe"
node_script = (
    "const fs=require('node:fs');"
    "fs.appendFileSync(process.env.GITHUB_OUTPUT, 'closed-before-wait\\n');"
    "process.stdout.write('ready\\n');"
    "process.stdin.once('data',()=>process.exit(0));"
)
node_argv = [
    "node", "--jitless", "--disable-wasm-trap-handler",
    "--max-old-space-size=64", "--v8-pool-size=1", "-e", node_script,
]
with tempfile.TemporaryDirectory(prefix="dotunnel-pr12-red-") as directory:
    output_path = os.path.join(directory, "github-output")
    output_fd = os.open(output_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    os.fchmod(output_fd, 0o600)
    output_info = os.fstat(output_fd)
    child = subprocess.Popen(
        node_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": directory,
             "GITHUB_OUTPUT": output_path}, close_fds=True,
    )
    try:
        ready = bytearray()
        deadline = time.monotonic() + 3
        while b"\n" not in ready:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([child.stdout.fileno()], [], [], remaining)[0]:
                raise AssertionError("bounded Node readiness timed out")
            chunk = os.read(child.stdout.fileno(), 64 - len(ready))
            if not chunk:
                raise AssertionError("Node child closed before readiness")
            ready.extend(chunk)
            if len(ready) > 64:
                raise AssertionError("Node readiness record exceeded its bound")
        if bytes(ready) != b"ready\n":
            raise AssertionError("Node child did not signal readiness")
        identity = runner_runtime.observe_process(child.pid)
        identity = replace(
            identity, uid=0, gid=0, cap_eff="0000000000000000",
            cap_prm="0000000000000000", cap_bnd="0000000000000000",
            cap_amb="0000000000000000", no_new_privs=1,
        )
        if any((row[1], row[2]) == (output_info.st_dev, output_info.st_ino)
               for row in identity.held_fds):
            raise AssertionError("baseline fixture unexpectedly held GITHUB_OUTPUT")
        try:
            runner_runtime._verify_publisher_child(identity, runtime_token, output_info)
        except runner_runtime.RuntimeFailure as error:
            print("BEFORE_FIX transient SDK output:", error.code, flush=True)
            if error.code != "publisher-output-fd-not-held":
                raise
        else:
            raise AssertionError("baseline verifier did not reject transient output FD")
    finally:
        if child.poll() is None:
            child.stdin.write(b"exit\n")
            child.stdin.flush()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        child.stdin.close()
        child.stdout.close()
        os.close(output_fd)
claims = {"scp": "Actions.Results:run-backend-123:job-backend-456"}
segment = __import__("base64").urlsafe_b64encode(__import__("json").dumps(claims).encode()).decode().rstrip("=")
try:
    runner_runtime._runtime_claims("e30." + segment + ".c2ln")
except runner_runtime.RuntimeFailure as error:
    print("BEFORE_FIX official Results scope:", error.code, flush=True)
    if error.code != "runtime-backend-identity-unavailable":
        raise
else:
    raise AssertionError("reviewed baseline unexpectedly accepted the official Results scope")
print("Kernel acceptance: NOT_VERIFIED; credentials/capabilities synthetic; owned Node process reaped", flush=True)
raise SystemExit(1)
