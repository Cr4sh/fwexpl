@echo off

set BIN_DIR=..\bin\
set LIB_DIR=..\lib\

:: delete old files
del %BIN_DIR%\fwexpl_app_amd64.*
del %LIB_DIR%\libdsebypass_amd64.*
del %LIB_DIR%\libfwexpl_amd64.*
del %BIN_DIR%\fwexpl_amd64.*

echo ------------------------------------------------------
echo  BUILDING DRIVER
echo ------------------------------------------------------

:: build driver
cd driver
nmake /f makefile_amd64 clean
nmake /f makefile_amd64
cd ..

if not exist %BIN_DIR%\fwexpl_amd64.sys goto end

echo ------------------------------------------------------
echo  BUILDING LIBDSEBYPASS
echo ------------------------------------------------------

:: build library
cd libdsebypass
nmake /f makefile_amd64 clean
nmake /f makefile_amd64
cd ..

if not exist %LIB_DIR%\libdsebypass_amd64.lib goto end

echo ------------------------------------------------------
echo  BUILDING LIBFWEXPL
echo ------------------------------------------------------

:: build library
cd libfwexpl
nmake /f makefile_amd64 clean
nmake /f makefile_amd64
cd ..

if not exist %LIB_DIR%\libfwexpl_amd64.lib goto end

echo ------------------------------------------------------
echo  BUILDING APPLICATION
echo ------------------------------------------------------

:: build application
cd application
nmake /f makefile_amd64 clean
nmake /f makefile_amd64
cd ..

if not exist %BIN_DIR%\fwexpl_app_amd64.exe goto end

echo ------------------------------------------------------
echo  DONE
echo ------------------------------------------------------

:end
