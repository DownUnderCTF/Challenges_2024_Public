import tomllib
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
import shutil
import subprocess
import os

BUILD_FOLDER = "landingzone/"

print("[*] Reading config...")
with open("challenge.toml", "rb") as f:
    config = tomllib.load(f)

try:
    print("[*] Creating tmp folder", BUILD_FOLDER)
    Path(BUILD_FOLDER).mkdir(parents=True, exist_ok=False)
    Path(BUILD_FOLDER + "chall/").mkdir(parents=True, exist_ok=False)
except Exception as e:
    raise e

env = Environment(loader=FileSystemLoader(config["folders"]["templates"]))

print("[*] Constructing loot/ folder")
shutil.copytree(config["folders"]["templates"] + "loot/", BUILD_FOLDER + "chall/loot/")
template = env.get_template('target_loot.jinja2').render(jwt_secret=config["JWT_SECRET"])
with open(BUILD_FOLDER + "chall/loot/" + config["filename"], "w") as f:
    f.write(template)

print("[*] Populating flag.txt")
template = env.get_template('flag.jinja2').render(flag=config["flag"])
with open(BUILD_FOLDER + "chall/flag.txt", "w") as f:
    f.write(template)

print("[*] Populating secret.txt")
template = env.get_template('secret.jinja2').render(jwt_secret=config["JWT_SECRET"])
with open(BUILD_FOLDER + "chall/secret.txt", "w") as f:
    f.write(template)

print("[*] Populating Rocket.toml")
template = env.get_template('Rocket.jinja2').render()
with open(BUILD_FOLDER + "chall/Rocket.toml", "w") as f:
    f.write(template)