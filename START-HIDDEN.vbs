Set WshShell = CreateObject("WScript.Shell")
' One-click hidden (no console) — double-click this for clean launch
WshShell.Run "pythonw app_tk.py", 0, False
