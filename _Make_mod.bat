@echo off
cls

REM set PS3SDK=/c/PSDK3v2
REM set PS3DEV=/c/PSDK3v2/ps3dev2
REM set WIN_PS3SDK=C:/PSDK3v2
REM set PATH=%WIN_PS3SDK%/mingw/msys/1.0/bin;%WIN_PS3SDK%/mingw/bin;%PS3DEV%/ppu/bin;%SCETOOL%;
REM set SCETOOL=C:\PSDK3v2\ps3dev2\bin

make -f Makefile.mak clean
make -f Makefile.mak all
rm -f mod/*.o mod/*.exe

pause