import subprocess

def execute_ansible(commands):
    for command in commands:
        subprocess.run(command, shell=True)
