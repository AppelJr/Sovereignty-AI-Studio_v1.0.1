# Offline local tool dispatcher

The canonical dispatcher is `backend/integration/offline_tool_dispatcher.py`.
It is deliberately fixed to the `echo` tool and `/bin/echo`; callers cannot
load or override an executable map. It uses `shell=False`, a controlled
environment, bounded argument sizes, a five-second deadline, and one aggregate
64 KiB stdout/stderr byte budget enforced while reading.

The DevAssist420 endpoint is `POST /api/devassist420/tools/execute`. It requires
a valid canonical owner session carrying the explicit `local.tool.execute`
capability. The request is not an authorization source. DevAssist420 verifies
the session and SCAR chain before dispatch, then records ALLOW, DENY, or FAIL
with the request ID, capability reference, tool identity, exit code, output
lengths, and SHA3-512 digests. Raw output is returned to the caller but is not
copied into SCAR.

The dispatcher is an execution mechanism only. It cannot grant capabilities,
select another executable, invoke a shell, access the network, or authorize
repository mutations. Additional tools require a separately reviewed code
change and a new policy decision; there is no runtime `tools.json` override.
