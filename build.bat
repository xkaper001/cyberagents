@echo off
REM Build the Windows .exe. Run on a Windows machine with python.org Python
REM installed (its installer includes tkinter). Produces dist\cyberagents.exe.
python -m pip install --upgrade pyinstaller
pyinstaller --onefile --windowed --name cyberagents gui.py
echo.
echo Done. Share: dist\cyberagents.exe
pause
