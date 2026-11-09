"""刻意含有安全問題的範例，用來測試掃描結果（金鑰皆為公開範例值）。"""

import hashlib
import os
import pickle
import subprocess
import yaml


def run_command(user_input):
    os.system("echo " + user_input)
    return subprocess.run("ls " + user_input, shell=True, capture_output=True)


def calculate(data):
    return hashlib.md5(data).hexdigest()


def load_config(raw):
    return yaml.load(raw, Loader=yaml.Loader)


def load_object(raw):
    return pickle.loads(raw)


def run_code(expression):
    return eval(expression)


PASSWORD = "demo-password-value"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgres://admin:supersecret@db.internal/app"
