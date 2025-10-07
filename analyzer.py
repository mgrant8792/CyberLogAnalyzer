#!/usr/bin/env python3
"""
CyberLogAnalyzer
Parses auth/syslog-style logs, counts failed login attempts, detects brute-force spikes,
and writes a CSV summary report.

Run example:
  python analyzer.py --log sample_logs/auth.log.example --out report.csv --threshold 3 --window 120
"""

import argparse, re, csv, os
from collections import defaultdict, deque
from datetime import datetime, timedelta

SSH_FAILED_RE = re.compile(r".*sshd.*[Ff]ailed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
AUTH_FAIL_RE  = re.compile(r".*(?:authentication failure|Failed password).*rhost[=: ](?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
TS_RE = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")

def parse_ts(line:str)->datetime|None:
    m=TS_RE.match(line)
    if not m: return None
    mon=MONTHS.get(m['mon'],1)
    d=int(m['day'])
    h,mn,s=map(int,m['time'].split(':'))
    try: return datetime(datetime.now().year,mon,d,h,mn,s)
    except: return None

def analyze(path:str,thresh:int,window:int):
    ip_events=defaultdict(list); dq=defaultdict(deque); susp=set()
    with open(path,encoding="utf8",errors="ignore") as f:
        for ln in f:
            ts=parse_ts(ln) or datetime.now()
            m=SSH_FAILED_RE.match(ln) or AUTH_FAIL_RE.match(ln)
            if not m: continue
            ip=m.group("ip"); ip_events[ip].append((ts,ln))
            q=dq[ip]; q.append(ts)
            cut=ts-timedelta(seconds=window)
            while q and q[0]<cut: q.popleft()
            if len(q)>=thresh: susp.add(ip)
    return ip_events,susp

def write_csv(outf:str,ip_events,susp):
    parent=os.path.dirname(outf)
    if parent and not os.path.isdir(parent): os.makedirs(parent,exist_ok=True)
    with open(outf,"w",newline='',encoding="utf8") as f:
        w=csv.writer(f); w.writerow(["ip","fail_count","suspicious","sample"])
        for ip,ev in sorted(ip_events.items(),key=lambda x:len(x[1]),reverse=True):
            w.writerow([ip,len(ev),("YES" if ip in susp else "NO"),ev[0][1][:80]])
    print(f"[+] CSV written to {os.path.abspath(outf)}")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--log",required=True);p.add_argument("--out",default="report.csv")
    p.add_argument("--threshold",type=int,default=3);p.add_argument("--window",type=int,default=120)
    a=p.parse_args()

    print(f"[DEBUG] reading {a.log}")
    ips,susp=analyze(a.log,a.threshold,a.window)
    print(f"[+] {len(ips)} IPs with fails, {len(susp)} suspicious")
    write_csv(a.out,ips,susp)

if __name__=="__main__": main()
