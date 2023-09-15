import subprocess

def execute_ansible(commands, output_file=None):
    for command in commands:
        if output_file:
            with open(output_file, 'a') as f:
                subprocess.run(command, shell=True, stdout=f, stderr=f)
        else:
            subprocess.run(command, shell=True)

