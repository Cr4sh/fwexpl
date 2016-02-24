@echo off

set BIN_DIR=..\bin\
set LIB_DIR=..\lib\

:: delete old files
del %BIN_DIR%\fwexpl_app_i386.*
del %LIB_DIR%\libdsebypass_i386.*
del %LIB_DIR%\libfwexpl_i386.*
del %BIN_DIR%\fwexpl_i386.*

echo ------------------------------------------------------
echo  BUILDING DRIVER
echo ------------------------------------------------------

:: build driver
cd driver
nmake /f makefile_i386 clean
nmake /f makefile_i386
cd ..

if not exist %BIN_DIR%\fwexpl_i386.sys goto end

echo ------------------------------------------------------
echo  BUILDING LIBDSEBYPASS
echo ------------------------------------------------------

:: build library
cd libdsebypass
nmake /f makefile_i386 clean
nmake /f makefile_i386
cd ..

if not exist %LIB_DIR%\libdsebypass_i386.lib goto end

echo ------------------------------------------------------
echo  BUILDING LIBFWEXPL
echo ------------------------------------------------------

:: build library
cd libfwexpl
nmake /f makefile_i386 clean
nmake /f makefile_i386
cd ..

if not exist %LIB_DIR%\libfwexpl_i386.lib goto end

echo ------------------------------------------------------
echo  BUILDING APPLICATION
echo ------------------------------------------------------

:: build application
cd application
nmake /f makefile_i386 clean
nmake /f makefile_i386
cd ..

if not exist %BIN_DIR%\fwexpl_app_i386.exe goto end

echo ------------------------------------------------------
echo  DONE
echo ------------------------------------------------------

:end
