import os
import pandas as pd
from collections import Counter

RAW_CSV = "data/cowrie/raw/cowrie_raw.csv"
OUT_CSV = "data/cowrie/processed/cowrie_features.csv"

os.makedirs("data/cowrie/processed", exist_ok=True)

SUSPICIOUS_COMMANDS = [
    "wget", "curl", "chmod", "./",
    "nc", "ncat", "perl", "python",
    "busybox", "tftp"
]

def build_features(df: pd.DataFrame) -> pd.DataFrame:
    # Clean
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["src_ip"] = df["src_ip"].fillna("0.0.0.0")
    df["login_success"] = df["login_success"].map(
        {"True": 1, "False": 0, True: 1, False: 0}
    ).fillna(0)
    df["command"] = df["command"].fillna("")

    # Get list of commands per IP
    commands_by_ip = df.groupby("src_ip")["command"].apply(
        lambda x: [c for c in x.astype(str).tolist() if c.strip() and c != "nan" and c != ""]
    ).reset_index(name="commands_list")

    # Main aggregation
    features = df.groupby("src_ip").agg(
        total_events=("event_id", "count"),
        unique_sessions=("session_id", "nunique"),
        failed_logins=("login_success", lambda x: (x == 0).sum()),
        success_logins=("login_success", lambda x: (x == 1).sum()),
        unique_usernames=("username", "nunique"),
        unique_passwords=("password", "nunique"),
        unique_dst_ports=("dst_port", "nunique"),
        unique_protocols=("protocol", "nunique"),
        commands_executed=("command", lambda x: (x.astype(str).str.strip() != "").sum()),
        files_downloaded=("file_downloaded", lambda x: (x != "").sum()),
        c2_connections=("c2_ip", lambda x: (x != "").sum()),
        has_payload=("sha256_payload", lambda x: x.notna().sum()),
        avg_session_duration=("session_duration_sec", "mean"),
        total_bytes_sent=("bytes_sent", "sum"),
        total_bytes_received=("bytes_received", "sum"),
        high_severity_events=("severity", lambda x: (x == "high").sum()),
        medium_severity_events=("severity", lambda x: (x == "medium").sum()),
        unique_mitre_techniques=("mitre_technique_id", "nunique"),
        unique_attack_types=("attack_type", "nunique"),
        compromised_count=("alert_tag", lambda x: (x == "compromised_login").sum()),
    ).reset_index()

    # Merge command lists
    features = features.merge(commands_by_ip, on="src_ip", how="left")
    features["commands_list"] = features["commands_list"].apply(
        lambda x: x if isinstance(x, list) else []
    )

    # Get top commands per IP
    def get_top_commands(cmds):
        if not cmds:
            return "none"
        counter = Counter(cmds)
        top5 = counter.most_common(5)
        return ", ".join([f"{cmd}({count})" for cmd, count in top5])

    def get_all_commands_unique(cmds):
        if not cmds:
            return "none"
        return ", ".join(list(dict.fromkeys(cmds))[:10])  # Top 10 unique commands

    features["top_commands"] = features["commands_list"].apply(get_top_commands)
    features["all_commands_unique"] = features["commands_list"].apply(get_all_commands_unique)
    features["unique_commands"] = features["commands_list"].apply(lambda x: len(set(x)))
    features["suspicious_command_count"] = features["commands_list"].apply(
        lambda cmds: sum(any(sc in cmd.lower() for sc in SUSPICIOUS_COMMANDS) for cmd in cmds)
    )
    features["uses_downloader"] = features["commands_list"].apply(
        lambda cmds: int(any(("wget" in c.lower() or "curl" in c.lower()) for c in cmds))
    )
    features["exec_chain_detected"] = features["commands_list"].apply(
        lambda cmds: int(
            any("wget" in c.lower() for c in cmds) and 
            any("chmod" in c.lower() for c in cmds)
        )
    )

    # Derived metrics
    total = features["total_events"]
    features["fail_rate"] = features["failed_logins"] / (total + 1)
    features["success_rate"] = features["success_logins"] / (total + 1)
    features["user_reuse_ratio"] = 1 - (features["unique_usernames"] / (features["failed_logins"] + 1))
    features["cmd_per_session"] = features["commands_executed"] / (features["unique_sessions"] + 1)
    features["bytes_ratio"] = features["total_bytes_sent"] / (features["total_bytes_received"] + 1)

    # Threat score
    features["threat_score"] = (
        features["high_severity_events"] * 2 +
        features["medium_severity_events"] +
        features["c2_connections"] * 3 +
        features["files_downloaded"] * 2 +
        features["has_payload"] * 2 +
        features["suspicious_command_count"] * 2 +
        features["exec_chain_detected"] * 5
    ) / (total + 1)

    # Time features
    def time_features(g):
        ts = g["timestamp"].dropna().sort_values()
        if len(ts) < 2:
            return pd.Series({"connection_rate": 0, "burst_score": 0})
        duration = max((ts.iloc[-1] - ts.iloc[0]).total_seconds() / 60, 1)
        rate = len(ts) / duration
        burst = 1 / (ts.diff().dt.total_seconds().std() + 1)
        return pd.Series({"connection_rate": rate, "burst_score": burst})

    tf = df.groupby("src_ip").apply(time_features).reset_index()
    features = features.merge(tf, on="src_ip", how="left").fillna(0)

    return features

def main():
    df = pd.read_csv(RAW_CSV)
    features = build_features(df)
    features.to_csv(OUT_CSV, index=False)
    print("[✔] Saved:", OUT_CSV)
    print("[i] Rows:", len(features))
    print("[i] New fields: top_commands, all_commands_unique, commands_list")
    print("[i] Columns:", list(features.columns))

if __name__ == "__main__":
    main()