import datetime

def log_event(event: str):
    with open("system_logs.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} - {event}\n")