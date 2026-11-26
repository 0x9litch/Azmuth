import asyncio, os, sys
import asyncssh
HOME = sys.argv[1]
FAKEBIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fakebin")
PORT = int(sys.argv[2])
REMOTE_HOME = f"{HOME}/remote"
SERVER_PASSWORD = "serverpass"
STATIC_KEYS = []


ACTIVE = {"now": 0, "max": 0}
MAX_SESSIONS = 10  # like OpenSSH's default MaxSessions


def _record():
    with open(f"{HOME}/.channels", "w") as f:
        f.write(f"{ACTIVE['now']} {ACTIVE['max']}")


class CountedProcess(asyncssh.SSHServerProcess):
    def __init__(self, owner, *args):
        super().__init__(*args)
        self._owner = owner
        self._counted = True

    def connection_lost(self, exc):
        if self._counted:
            self._counted = False
            self._owner.active -= 1
            ACTIVE["now"] -= 1
            _record()
        super().connection_lost(exc)


class FakeServer(asyncssh.SSHServer):
    """Password auth + public keys from a static list and REMOTE_HOME/.ssh/authorized_keys."""

    def begin_auth(self, username):
        return True

    def connection_made(self, conn):
        self.active = 0

    def session_requested(self):
        # Refuse like sshd does once MaxSessions channels are open
        # on THIS connection (commands and SFTP both count).
        if self.active >= MAX_SESSIONS:
            return False
        self.active += 1
        ACTIVE["now"] += 1
        ACTIVE["max"] = max(ACTIVE["max"], self.active)
        _record()
        return CountedProcess(self, handle_process, DenyingSFTP, 3, False)


    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == SERVER_PASSWORD

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        candidates = list(STATIC_KEYS)
        try:
            for line in open(f"{REMOTE_HOME}/.ssh/authorized_keys"):
                line = line.strip()
                if line:
                    candidates.append(asyncssh.import_public_key(line))
        except OSError:
            pass
        return any(c.public_data == key.public_data for c in candidates)
class DenyingSFTP(asyncssh.SFTPServer):
    """Local-filesystem SFTP that denies anything under /protected/."""

    def _check(self, path):
        p = path.decode() if isinstance(path, bytes) else path
        if "/protected/" in p or p.endswith("/protected-dir/x"):
            raise asyncssh.SFTPPermissionDenied("Permission denied")

    def stat(self, path):
        self._check(path)
        return super().stat(path)

    def lstat(self, path):
        self._check(path)
        return super().lstat(path)

    def open(self, path, pflags, attrs):
        self._check(path)
        return super().open(path, pflags, attrs)

    def mkdir(self, path, attrs):
        self._check(path)
        return super().mkdir(path, attrs)

    def remove(self, path):
        self._check(path)
        p = path.decode() if isinstance(path, bytes) else path
        if "/nodelete/" in p:  # readable, but deleting needs sudo
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        return super().remove(path)


async def handle_process(process):
    env = dict(os.environ, PATH=f"{FAKEBIN}:{os.environ['PATH']}", HOME=REMOTE_HOME)
    proc = await asyncio.create_subprocess_shell(
        process.command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        executable="/bin/bash",
    )
    await process.redirect(stdin=proc.stdin, stdout=proc.stdout, stderr=proc.stderr)
    rc = await proc.wait()
    await process.stdout.drain()
    process.exit(rc)


async def start_server():
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    os.makedirs(f"{HOME}/.ssh", exist_ok=True)
    client_key.write_private_key(f"{HOME}/.ssh/id_test")
    STATIC_KEYS.append(client_key.convert_to_public())
    os.makedirs(REMOTE_HOME, exist_ok=True)

    server = await asyncssh.listen(
        "127.0.0.1",
        PORT,
        server_host_keys=[host_key],
        server_factory=FakeServer,
        allow_scp=False,
    )
    return server, host_key.get_fingerprint("sha256")



async def amain():
    server, fp = await start_server()
    open(f"{HOME}/.fp", "w").write(fp)
    await asyncio.Event().wait()
asyncio.run(amain())
