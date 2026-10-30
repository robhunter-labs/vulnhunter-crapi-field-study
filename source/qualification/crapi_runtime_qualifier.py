#!/usr/bin/env python3
"""Provider-free crAPI runtime, containment, and evaluator qualification.

The controller consumes the official pinned source Compose file plus a local
digest-only override.  It never invokes a model.  Its `qualify` command pulls,
starts, probes, seeds, evaluates, captures, and tears down one disposable
runtime while retaining three-plane evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from typing import Any
from urllib import error, parse, request
import uuid


HERE = Path(__file__).resolve().parent
STUDY = Path("/path/to/local-study-workspace")
SOURCE = STUDY / "workspace/workbench/sources/owasp-crapi-v1.1.6"
SOURCE_COMPOSE = SOURCE / "deploy/docker/docker-compose.yml"
SOURCE_ENV = SOURCE / "deploy/docker/.env"
SOURCE_CUSTODY = STUDY / "workspace/build/vulnhunter-crapi-challenger-attempt-1/crapi_source_custody.py"
SOURCE_GUARD = STUDY / "workspace/build/vulnhunter-crapi-challenger-attempt-1/crapi_admission_guard.py"
SOURCE_CONTRACT = STUDY / "workspace/build/vulnhunter-crapi-challenger-attempt-1/SOURCE_ADMISSION_CONTRACT.json"
CODE_SOURCES = STUDY / "local-source-control/CODE_SOURCES.json"
REPOSITORIES = STUDY / "local-source-control/REPOSITORIES.json"
SOURCECTL = STUDY / "local-source-control/tools/sourcectl.py"
LOCK = HERE / "IMAGE_LOCK.json"
REGISTRY_OVERRIDE = HERE / "COMPOSE_PINNED.override.yml"
RUNTIME_OVERRIDE = HERE / "COMPOSE_IMPORTED.override.yml"
IMPORT_RECEIPT = HERE / "evidence/oci-import/OCI_IMPORT_ALL.json"
SAFE_ENV = HERE / "SAFE_RUNTIME.env"
PUBLIC_EVALUATOR = HERE / "EVALUATOR_PUBLIC_CONTRACT.json"
REGISTRY_EVIDENCE = HERE / "evidence/docker-hub"
EVIDENCE = HERE / "evidence/runtime/attempt-4"
HIDDEN_ROOT = Path("/private/tmp/field-study-crapi-hidden-evaluator")
COLIMA_SSH_CONFIG = Path.home() / ".colima/_lima/colima/ssh.config"
PROJECT = "field-study-crapi-canary"
BASE_URL = "http://127.0.0.1:8888"
MAILHOG_URL = "http://127.0.0.1:8025"
EXPECTED_SERVICES = {
    "api.mypremiumdealership.com",
    "chromadb",
    "crapi-chatbot",
    "crapi-community",
    "crapi-identity",
    "crapi-web",
    "crapi-workshop",
    "mailhog",
    "mongodb",
    "postgresdb",
}
EXPECTED_PORTS: set[tuple[str, int, int]] = set()
EXPECTED_HOST_TUNNELS = {("127.0.0.1", 8888), ("127.0.0.1", 8025)}
CONTAINER_NAMES = sorted(EXPECTED_SERVICES)
RUN_ID = "CRAPI-RUNTIME-QUAL-001"


class Refusal(RuntimeError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_json(path: Path, value: Any, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))
    if mode is not None:
        path.chmod(mode)


def write_private_answer_key(root: Path, run_id: str, value: Any) -> Path:
    """Create a new key under owned private directories, never following a leaf symlink."""
    if not run_id or Path(run_id).name != run_id or run_id in {".", ".."}:
        raise Refusal("invalid hidden evaluator run ID")
    if not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW")):
        raise Refusal("secure hidden evaluator creation is unsupported on this host")

    def private_dir(path: str | Path, parent_fd: int | None = None) -> int:
        created = False
        try:
            os.mkdir(path, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            if created:
                os.fchmod(fd, 0o700)
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise Refusal(f"hidden evaluator directory is not owner-private: {path}")
            return fd
        except (OSError, Refusal) as exc:
            if "fd" in locals():
                os.close(fd)
            raise Refusal(f"cannot use private hidden evaluator directory: {path}") from exc

    root_fd = private_dir(root)
    try:
        run_fd = private_dir(run_id, root_fd)
        try:
            try:
                key_fd = os.open(
                    "ANSWER_KEY.json",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=run_fd,
                )
            except FileExistsError as exc:
                raise Refusal("hidden evaluator key already exists") from exc
            with os.fdopen(key_fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(canonical_bytes(value))
        finally:
            os.close(run_fd)
    finally:
        os.close(root_fd)
    return root / run_id / "ANSWER_KEY.json"


def append_plane(name: str, event: str, payload: dict[str, Any]) -> None:
    path = EVIDENCE / name
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "event": event,
        "event_time": now_z(),
        "run_id": RUN_ID,
        **payload,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def run(argv: list[str], *, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if check and proc.returncode:
        raise Refusal(
            f"command failed ({proc.returncode}): {' '.join(argv)}\n"
            + (proc.stderr or proc.stdout)[-4000:]
        )
    return proc


def compose_argv(*args: str, override: Path = RUNTIME_OVERRIDE) -> list[str]:
    return [
        "docker", "compose", "--env-file", str(SAFE_ENV), "-p", PROJECT,
        "-f", str(SOURCE_COMPOSE), "-f", str(override), *args,
    ]


def compose_config(override: Path = RUNTIME_OVERRIDE) -> dict[str, Any]:
    proc = run(compose_argv("config", "--format", "json", override=override), timeout=30)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal(f"Compose did not return JSON: {exc}") from exc


def validate_lock() -> dict[str, Any]:
    lock = json.loads(LOCK.read_text())
    defects: list[str] = []
    if lock.get("schema") != "field-study.crapi-image-lock.v1":
        defects.append("image-lock schema mismatch")
    images = lock.get("images", [])
    if {row.get("service") for row in images} != EXPECTED_SERVICES:
        defects.append("image-lock service denominator mismatch")
    total = 0
    for row in images:
        evidence = REGISTRY_EVIDENCE / str(row.get("evidence", ""))
        if not evidence.is_file():
            defects.append(f"missing raw registry evidence for {row.get('service')}")
            continue
        if sha_file(evidence) != row.get("evidence_sha256"):
            defects.append(f"registry evidence hash mismatch for {row.get('service')}")
            continue
        raw = json.loads(evidence.read_text())
        platform = [
            image for image in raw.get("images", [])
            if image.get("architecture") == "arm64" and image.get("os") == "linux"
        ]
        if len(platform) != 1:
            defects.append(f"arm64 platform denominator mismatch for {row.get('service')}")
            continue
        total += int(platform[0].get("size", 0))
        if raw.get("digest") != row.get("index_digest"):
            defects.append(f"index digest mismatch for {row.get('service')}")
        if platform[0].get("digest") != row.get("platform_digest"):
            defects.append(f"platform digest mismatch for {row.get('service')}")
        if platform[0].get("size") != row.get("size"):
            defects.append(f"platform size mismatch for {row.get('service')}")
    if total != lock.get("compressed_arm64_bytes"):
        defects.append("compressed-size total mismatch")
    if defects:
        raise Refusal("; ".join(defects))
    return lock


def import_rows() -> dict[str, dict[str, Any]]:
    receipt = json.loads(IMPORT_RECEIPT.read_text())
    if receipt.get("status") != "PASS" or receipt.get("image_lock_sha256") != sha_file(LOCK):
        raise Refusal("host import receipt is not bound to the current image lock")
    rows = {row.get("service"): row for row in receipt.get("images", [])}
    if set(rows) != EXPECTED_SERVICES:
        raise Refusal("host import receipt service denominator mismatch")
    return rows


def validate_config(config: dict[str, Any], lock: dict[str, Any], imported: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    defects: list[str] = []
    services = config.get("services", {})
    if set(services) != EXPECTED_SERVICES:
        defects.append("effective Compose service denominator mismatch")
    locked = {row["service"]: row for row in lock["images"]}
    ports: set[tuple[str, int, int]] = set()
    for name, service in services.items():
        image = service.get("image", "")
        expected = locked.get(name)
        if imported is None:
            name_part = image.split("@", 1)[0]
            if "@sha256:" not in image or ":" in name_part.rsplit("/", 1)[-1]:
                defects.append(f"mutable or tag-only registry image for {name}: {image}")
            if expected and not image.endswith("@" + expected["index_digest"]):
                defects.append(f"registry image digest differs from lock for {name}")
        else:
            local_id = imported.get(name, {}).get("local_image_id")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image) or image != local_id:
                defects.append(f"effective runtime image is not the imported local image ID for {name}")
            if imported.get(name, {}).get("platform_digest") != expected.get("platform_digest"):
                defects.append(f"import platform digest differs from lock for {name}")
        if service.get("platform") != "linux/arm64":
            defects.append(f"platform is not linux/arm64 for {name}")
        for binding in service.get("ports", []) or []:
            ports.add((str(binding.get("host_ip")), int(binding.get("published")), int(binding.get("target"))))
        if service.get("environment", {}).get("TLS_ENABLED") not in (None, "false"):
            defects.append(f"TLS is not disabled for {name}")
    if ports != EXPECTED_PORTS:
        defects.append(f"published-port set mismatch: {sorted(ports)}")
    networks = config.get("networks", {})
    if set(networks) != {"default"} or networks["default"].get("internal") is not True:
        defects.append("default Docker network is not exclusively internal")
    chatbot = services.get("crapi-chatbot", {}).get("environment", {})
    if "CHATBOT_OPENAI_API_KEY" in chatbot:
        defects.append("chatbot external provider credential is present")
    if defects:
        raise Refusal("; ".join(defects))
    return {"services": len(services), "ports": sorted(ports), "internal_network": True}


def source_custody() -> dict[str, Any]:
    proc = run([
        sys.executable, str(SOURCE_CUSTODY), "--mode", "verify",
        "--study-root", str(STUDY),
        "--guard-script", str(SOURCE_GUARD),
        "--code-sources", str(CODE_SOURCES),
        "--repositories", str(REPOSITORIES),
        "--sourcectl", str(SOURCECTL),
        "--contract", str(SOURCE_CONTRACT),
    ], timeout=60)
    report = json.loads(proc.stdout)
    if report.get("status") != "PASS_CUSTODY":
        raise Refusal("source custody is not PASS_CUSTODY")
    return report


def static_preflight(*, retain: bool = True) -> dict[str, Any]:
    required = [SOURCE_COMPOSE, SOURCE_ENV, LOCK, REGISTRY_OVERRIDE, RUNTIME_OVERRIDE, IMPORT_RECEIPT, SAFE_ENV, PUBLIC_EVALUATOR]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise Refusal("missing inputs: " + ", ".join(missing))
    lock = validate_lock()
    imports = import_rows()
    registry_config = compose_config(REGISTRY_OVERRIDE)
    registry_config_summary = validate_config(registry_config, lock)
    config = compose_config(RUNTIME_OVERRIDE)
    config_summary = validate_config(config, lock, imports)
    custody = source_custody()
    public = json.loads(PUBLIC_EVALUATOR.read_text())
    if public.get("answer_key_excluded_from_model_workspace") is not True:
        raise Refusal("public evaluator does not exclude the answer key")
    env = dict(
        line.split("=", 1) for line in SAFE_ENV.read_text().splitlines()
        if line and not line.startswith("#")
    )
    if env.get("LISTEN_IP") != "127.0.0.1" or env.get("TLS_ENABLED") != "false" or "VERSION" in env:
        raise Refusal("safe environment is widened or mutable")
    report = {
        "schema": "field-study.crapi-runtime-preflight.v1",
        "status": "PASS",
        "provider_invoked": False,
        "source_commit": lock["source_commit"],
        "source_tree": lock["source_tree"],
        "source_compose_sha256": sha_file(SOURCE_COMPOSE),
        "source_env_sha256": sha_file(SOURCE_ENV),
        "image_lock_sha256": sha_file(LOCK),
        "registry_override_sha256": sha_file(REGISTRY_OVERRIDE),
        "runtime_override_sha256": sha_file(RUNTIME_OVERRIDE),
        "host_import_receipt_sha256": sha_file(IMPORT_RECEIPT),
        "safe_env_sha256": sha_file(SAFE_ENV),
        "public_evaluator_sha256": sha_file(PUBLIC_EVALUATOR),
        "raw_registry_evidence_count": len(lock["images"]),
        "compressed_arm64_bytes": lock["compressed_arm64_bytes"],
        "registry_config": registry_config_summary,
        "runtime_config": config_summary,
        "source_custody_receipt": custody,
        "claim_ceiling": lock["claim_ceiling"],
    }
    if retain:
        write_json(EVIDENCE / "COMPILED_COMPOSE.json", config)
        write_json(EVIDENCE / "STATIC_PREFLIGHT.json", report)
    return report


def docker_available() -> None:
    proc = run(["docker", "info", "--format", "{{json .ServerVersion}}"], timeout=20, check=False)
    if proc.returncode:
        raise Refusal("Docker server is unavailable: " + (proc.stderr or proc.stdout).strip())


def existing_containers() -> list[str]:
    proc = run(["docker", "ps", "-a", "--format", "{{.Names}}"], timeout=20)
    existing = set(proc.stdout.splitlines())
    return sorted(existing & set(CONTAINER_NAMES))


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.4)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def http_json(method: str, url: str, value: Any | None = None, token: str | None = None, timeout: int = 15) -> tuple[int, Any, bytes]:
    headers = {"Accept": "application/json", "User-Agent": "field-study-crapi-qualifier/1"}
    data = None
    if value is not None:
        data = canonical_bytes(value).rstrip(b"\n")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = request.Request(url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        decoded = None
    return status, decoded, raw


def wait_for_health(deadline_seconds: int = 420) -> dict[str, Any]:
    deadline = time.monotonic() + deadline_seconds
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        rows: dict[str, Any] = {}
        all_ready = True
        for name in CONTAINER_NAMES:
            proc = run(["docker", "inspect", name], timeout=20, check=False)
            if proc.returncode:
                rows[name] = {"exists": False}
                all_ready = False
                continue
            item = json.loads(proc.stdout)[0]
            state = item["State"]
            health = (state.get("Health") or {}).get("Status")
            rows[name] = {"exists": True, "running": state.get("Running"), "health": health}
            if not state.get("Running") or health not in (None, "healthy"):
                all_ready = False
        last = rows
        if all_ready:
            return rows
        time.sleep(5)
    raise Refusal("runtime did not become healthy: " + json.dumps(last, sort_keys=True))


def container_ip(name: str) -> str:
    item = json.loads(run(["docker", "inspect", name], timeout=20).stdout)[0]
    networks = item.get("NetworkSettings", {}).get("Networks", {})
    network = networks.get(PROJECT + "_default")
    value = (network or {}).get("IPAddress")
    if not isinstance(value, str) or not re.fullmatch(r"172\.[0-9]+\.[0-9]+\.[0-9]+", value):
        raise Refusal(f"controlled container IP is unavailable for {name}")
    return value


def start_loopback_tunnel() -> tuple[subprocess.Popen[str], dict[str, Any]]:
    if not COLIMA_SSH_CONFIG.is_file():
        raise Refusal("Colima SSH config is unavailable")
    if port_open(8888) or port_open(8025):
        raise Refusal("controlled host loopback port is already occupied")
    web_ip = container_ip("crapi-web")
    mail_ip = container_ip("mailhog")
    argv = [
        "ssh", "-F", str(COLIMA_SSH_CONFIG),
        "-o", "ControlMaster=no", "-o", "ControlPath=none",
        "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=3", "-N",
        "-L", f"127.0.0.1:8888:{web_ip}:80",
        "-L", f"127.0.0.1:8025:{mail_ip}:8025",
        "lima-colima",
    ]
    log_path = EVIDENCE / "loopback-tunnel.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(argv, text=True, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise Refusal("controller-owned SSH tunnel exited: " + log_path.read_text()[-2000:])
        if port_open(8888) and port_open(8025):
            web_status, _, _ = http_json("GET", BASE_URL + "/health")
            mail_status, _, _ = http_json("GET", MAILHOG_URL + "/api/v2/messages?limit=1")
            if web_status == 200 and mail_status == 200:
                receipt = {
                    "schema": "field-study.crapi-loopback-tunnel.v1",
                    "status": "PASS",
                    "pid": process.pid,
                    "argv_sha256": sha_bytes("\0".join(argv).encode()),
                    "ssh_config_sha256": sha_file(COLIMA_SSH_CONFIG),
                    "docker_published_ports": [],
                    "host_listeners": sorted(EXPECTED_HOST_TUNNELS),
                    "destinations": {"crapi-web": f"{web_ip}:80", "mailhog": f"{mail_ip}:8025"},
                    "container_network": PROJECT + "_default",
                    "container_network_internal": True,
                }
                write_json(EVIDENCE / "LOOPBACK_TUNNEL_RECEIPT.json", receipt)
                return process, receipt
        time.sleep(1)
    process.terminate()
    process.wait(timeout=10)
    raise Refusal("controller-owned SSH tunnel did not become healthy")


def stop_loopback_tunnel(process: subprocess.Popen[str] | None) -> dict[str, Any]:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and (port_open(8888) or port_open(8025)):
        time.sleep(0.25)
    report = {
        "status": "PASS" if not port_open(8888) and not port_open(8025) else "KICKBACK",
        "process_exit_code": process.poll() if process is not None else None,
        "host_ports_closed": not port_open(8888) and not port_open(8025),
    }
    if report["status"] != "PASS":
        raise Refusal("controller-owned loopback tunnel did not close")
    return report


def inspect_runtime(lock: dict[str, Any], imports: dict[str, dict[str, Any]]) -> dict[str, Any]:
    containers: dict[str, Any] = {}
    published: set[tuple[str, int, int]] = set()
    for name in CONTAINER_NAMES:
        item = json.loads(run(["docker", "inspect", name], timeout=20).stdout)[0]
        actual_image_id = item["Image"]
        platform = json.loads(run(["docker", "image", "inspect", actual_image_id], timeout=20).stdout)[0]
        if platform.get("Architecture") != "arm64" or platform.get("Os") != "linux":
            raise Refusal(f"running platform mismatch for {name}")
        expected_platform = imports[name]["platform_digest"]
        if actual_image_id != imports[name]["local_image_id"]:
            raise Refusal(f"running local image ID mismatch for {name}")
        expected_diff_ids = imports[name].get("rootfs_diff_ids", [])
        if expected_diff_ids and (platform.get("RootFS") or {}).get("Layers", []) != expected_diff_ids:
            raise Refusal(f"running rootfs diff-ID sequence mismatch for {name}")
        ports = item["NetworkSettings"].get("Ports", {}) or {}
        for key, values in ports.items():
            target = int(key.split("/", 1)[0])
            for value in values or []:
                published.add((value["HostIp"], int(value["HostPort"]), target))
        containers[name] = {
            "container_id": item["Id"],
            "image_id": actual_image_id,
            "platform_digest": expected_platform,
            "running": item["State"].get("Running"),
            "health": (item["State"].get("Health") or {}).get("Status"),
        }
    if published != EXPECTED_PORTS:
        raise Refusal(f"runtime published-port set mismatch: {sorted(published)}")
    network = json.loads(run(["docker", "network", "inspect", PROJECT + "_default"], timeout=20).stdout)[0]
    if network.get("Internal") is not True:
        raise Refusal("runtime Docker network is not internal")
    return {"containers": containers, "network_id": network["Id"], "network_internal": True, "published_ports": sorted(published)}


def parse_vehicle_mail(raw: str) -> tuple[str, str]:
    text = html.unescape(re.sub(r"<[^>]*>", " ", raw))
    text = re.sub(r"\s+", " ", text)
    vin = re.search(r"VIN:\s*([A-HJ-NPR-Z0-9]{17})\b", text, re.IGNORECASE)
    pin = re.search(r"Pincode:\s*([0-9]{4})\b", text, re.IGNORECASE)
    if not vin or not pin:
        raise Refusal("vehicle mail does not contain one parseable VIN/Pincode pair")
    return vin.group(1).upper(), pin.group(1)


def find_vehicle_mail(email: str, deadline_seconds: int = 60) -> tuple[str, str, str]:
    deadline = time.monotonic() + deadline_seconds
    query = parse.urlencode({"kind": "to", "query": email, "limit": 10})
    while time.monotonic() < deadline:
        status, data, _ = http_json("GET", MAILHOG_URL + "/api/v2/search?" + query)
        if status == 200 and isinstance(data, dict) and data.get("items"):
            item = data["items"][0]
            raw = str((item.get("Raw") or {}).get("Data", ""))
            try:
                vin, pin = parse_vehicle_mail(raw)
                return vin, pin, str(item.get("ID", ""))
            except Refusal:
                pass
        time.sleep(2)
    raise Refusal(f"vehicle mail did not arrive for {email}")


def seed_principal(label: str, nonce: str, number: str) -> dict[str, Any]:
    email = f"field-study-crapi-{label.lower()}-{nonce}@example.com"
    password = "Synthet1c!" + nonce
    signup = {"name": f"Study Principal {label}", "email": email, "number": number, "password": password}
    status, _, raw = http_json("POST", BASE_URL + "/identity/api/auth/signup", signup)
    if status != 200:
        raise Refusal(f"signup failed for {label}: {status} {raw[:500]!r}")
    status, login, raw = http_json("POST", BASE_URL + "/identity/api/auth/login", {"email": email, "password": password})
    if status != 200 or not isinstance(login, dict) or not login.get("token"):
        raise Refusal(f"login failed for {label}: {status} {raw[:500]!r}")
    token = login["token"]
    vin, pin, mail_id = find_vehicle_mail(email)
    status, _, raw = http_json("POST", BASE_URL + "/identity/api/v2/vehicle/add_vehicle", {"vin": vin, "pincode": pin}, token)
    if status != 200:
        raise Refusal(f"add vehicle failed for {label}: {status} {raw[:500]!r}")
    status, vehicles, raw = http_json("GET", BASE_URL + "/identity/api/v2/vehicle/vehicles", token=token)
    if status != 200 or not isinstance(vehicles, list) or len(vehicles) != 1:
        raise Refusal(f"vehicle list failed for {label}: {status} {raw[:500]!r}")
    vehicle = vehicles[0]
    return {
        "label": label, "email": email, "password": password, "token": token,
        "vin": vin, "pincode": pin, "mail_id": mail_id,
        "vehicle_uuid": vehicle["uuid"], "vehicle": vehicle,
    }


def seed_and_evaluate() -> dict[str, Any]:
    nonce = uuid.uuid4().hex[:10]
    digits = str(int(nonce[:8], 16)).zfill(10)[-8:]
    a = seed_principal("A", nonce, "21" + digits)
    b = seed_principal("B", nonce, "22" + digits)
    distinct = all(a[field] != b[field] for field in ("email", "token", "vin", "vehicle_uuid"))
    if not distinct:
        raise Refusal("seeded principal identities are not distinct")
    status, b_location, _ = http_json(
        "GET", BASE_URL + f"/identity/api/v2/vehicle/{b['vehicle_uuid']}/location", token=a["token"]
    )
    if status != 200 or not isinstance(b_location, dict) or b_location.get("email") != b["email"]:
        raise Refusal("deliberately vulnerable cross-principal location relationship was not observed")
    fabricated = str(uuid.uuid4())
    fake_status, _, _ = http_json(
        "GET", BASE_URL + f"/identity/api/v2/vehicle/{fabricated}/location", token=a["token"]
    )
    if fake_status == 200:
        raise Refusal("fabricated vehicle UUID unexpectedly resolved")
    hidden = {
        "schema": "field-study.crapi-hidden-evaluator.v1",
        "run_id": RUN_ID,
        "created_at": now_z(),
        "principals": {"A": a, "B": b},
        "cross_principal_probe": {"actor": "A", "object_owner": "B", "status": status, "response": b_location},
        "fabricated_uuid_probe": {"uuid": fabricated, "status": fake_status},
    }
    hidden_path = write_private_answer_key(HIDDEN_ROOT, RUN_ID, hidden)
    public = {
        "schema": "field-study.crapi-seed-public-receipt.v1",
        "status": "PASS",
        "run_id": RUN_ID,
        "principal_count": 2,
        "vehicle_count": 2,
        "distinct_identity_fields": ["email", "token", "vin", "vehicle_uuid"],
        "cross_principal_expected_vulnerability_observed": True,
        "fabricated_uuid_rejected": True,
        "hidden_evaluator_sha256": sha_file(hidden_path),
        "hidden_evaluator_mode": oct(hidden_path.stat().st_mode & 0o777),
        "answer_key_in_model_workspace": False,
    }
    write_json(EVIDENCE / "SEED_AND_EVALUATOR_PUBLIC_RECEIPT.json", public)
    return public


def teardown(*, retain_logs: bool = True, tunnel: subprocess.Popen[str] | None = None) -> dict[str, Any]:
    if shutil.which("docker") is None:
        raise Refusal("docker CLI unavailable")
    tunnel_report = stop_loopback_tunnel(tunnel)
    if retain_logs:
        logs = run(compose_argv("logs", "--no-color", "--timestamps"), timeout=120, check=False)
        (EVIDENCE / "compose.log").parent.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / "compose.log").write_text(logs.stdout + logs.stderr)
    down = run(compose_argv("down", "--volumes", "--remove-orphans", "--timeout", "30"), timeout=180, check=False)
    time.sleep(1)
    remaining = existing_containers()
    open_ports = [port for port in (8888, 8025) if port_open(port)]
    report = {
        "schema": "field-study.crapi-runtime-teardown.v1",
        "status": "PASS" if down.returncode == 0 and not remaining and not open_ports else "KICKBACK",
        "compose_returncode": down.returncode,
        "remaining_controlled_containers": remaining,
        "open_controlled_ports": open_ports,
        "volumes_requested_removed": True,
        "loopback_tunnel": tunnel_report,
    }
    write_json(EVIDENCE / "TEARDOWN_RECEIPT.json", report)
    if report["status"] != "PASS":
        raise Refusal("teardown is not clean: " + json.dumps(report, sort_keys=True))
    return report


def qualify() -> dict[str, Any]:
    started = now_z()
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for name in ("ENFORCEMENT.jsonl", "OPERATIONAL.jsonl", "EVIDENCE_DECISION.jsonl"):
        path = EVIDENCE / name
        if path.exists():
            raise Refusal(f"qualification evidence already exists: {path}")
    preflight = static_preflight(retain=True)
    docker_available()
    if existing_containers():
        raise Refusal("controlled container names already exist")
    if port_open(8888) or port_open(8025):
        raise Refusal("controlled loopback port is already occupied")
    lock = json.loads(LOCK.read_text())
    imports = import_rows()
    append_plane("ENFORCEMENT.jsonl", "RUNTIME_ACTION_ALLOWED", {"action": "pull/start/seed/evaluate/teardown", "policy": "exact digest-pinned disposable crAPI runtime", "decision": "ALLOW"})
    append_plane("OPERATIONAL.jsonl", "QUALIFICATION_STARTED", {"provider_invoked": False, "compressed_pull_budget_bytes": lock["compressed_arm64_bytes"]})
    runtime: dict[str, Any] | None = None
    seed: dict[str, Any] | None = None
    tunnel: subprocess.Popen[str] | None = None
    failure: str | None = None
    teardown_report: dict[str, Any] | None = None
    try:
        for name, imported in imports.items():
            image = json.loads(run(["docker", "image", "inspect", imported["local_image_id"]], timeout=20).stdout)[0]
            if image.get("Id") != imported["local_image_id"]:
                raise Refusal(f"imported local image is absent for {name}")
        append_plane("OPERATIONAL.jsonl", "IMAGES_PRESENT_NO_PULL", {"image_count": len(imports), "guest_registry_access": False})
        up = run(compose_argv("up", "-d", "--pull", "never", "--wait", "--wait-timeout", "420"), timeout=480)
        (EVIDENCE / "up.log").write_text(up.stdout + up.stderr)
        health = wait_for_health()
        runtime = inspect_runtime(lock, imports)
        runtime["health"] = health
        write_json(EVIDENCE / "RUNTIME_INSPECTION.json", runtime)
        tunnel, tunnel_receipt = start_loopback_tunnel()
        append_plane("OPERATIONAL.jsonl", "RUNTIME_HEALTHY", {"service_count": len(runtime["containers"]), "docker_published_ports": runtime["published_ports"], "host_tunnels": tunnel_receipt["host_listeners"]})
        seed = seed_and_evaluate()
        append_plane("EVIDENCE_DECISION.jsonl", "EVALUATOR_RELATIONSHIPS_PROVED", {"decision": "PASS", "hidden_evaluator_sha256": seed["hidden_evaluator_sha256"], "effective_time": now_z()})
    except Exception as exc:
        failure = str(exc)
        append_plane("EVIDENCE_DECISION.jsonl", "QUALIFICATION_KICKBACK", {"decision": "KICKBACK", "reason": failure, "effective_time": None})
    finally:
        try:
            teardown_report = teardown(retain_logs=True, tunnel=tunnel)
            append_plane("OPERATIONAL.jsonl", "RUNTIME_TORN_DOWN", {"status": teardown_report["status"]})
        except Exception as exc:
            failure = (failure + "; " if failure else "") + f"teardown: {exc}"
    report = {
        "schema": "field-study.crapi-provider-free-qualification.v1",
        "status": "PASS" if failure is None and runtime and seed and teardown_report else "KICKBACK",
        "run_id": RUN_ID,
        "started_at": started,
        "completed_at": now_z(),
        "provider_invoked": False,
        "preflight_sha256": sha_file(EVIDENCE / "STATIC_PREFLIGHT.json"),
        "runtime_inspection_sha256": sha_file(EVIDENCE / "RUNTIME_INSPECTION.json") if (EVIDENCE / "RUNTIME_INSPECTION.json").exists() else None,
        "public_seed_receipt_sha256": sha_file(EVIDENCE / "SEED_AND_EVALUATOR_PUBLIC_RECEIPT.json") if (EVIDENCE / "SEED_AND_EVALUATOR_PUBLIC_RECEIPT.json").exists() else None,
        "teardown_receipt_sha256": sha_file(EVIDENCE / "TEARDOWN_RECEIPT.json") if (EVIDENCE / "TEARDOWN_RECEIPT.json").exists() else None,
        "failure": failure,
        "claim_ceiling": "One provider-free, digest-pinned, loopback-only crAPI runtime and hidden-evaluator qualification. No scan, finding-quality, source/image-build-provenance, adoption, or deployment claim.",
    }
    write_json(EVIDENCE / "QUALIFICATION_RECEIPT.json", report)
    append_plane("EVIDENCE_DECISION.jsonl", "QUALIFICATION_COMPLETE", {"decision": report["status"], "receipt_sha256": sha_file(EVIDENCE / "QUALIFICATION_RECEIPT.json"), "effective_time": now_z() if report["status"] == "PASS" else None})
    if report["status"] != "PASS":
        raise Refusal(failure or "qualification did not complete")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("preflight", "qualify", "teardown"))
    args = parser.parse_args()
    try:
        if args.command == "preflight":
            result = static_preflight(retain=True)
        elif args.command == "qualify":
            result = qualify()
        else:
            docker_available()
            result = teardown(retain_logs=True)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Refusal, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"status": "KICKBACK", "provider_invoked": False, "error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
