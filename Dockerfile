FROM mcr.microsoft.com/windows/servercore:ltsc2022

# install build tools (cl.exe) - use VS Build Tools
SHELL ["powershell", "-Command"]

# copy source
COPY test_overflow.c C:/test/test_overflow.c
COPY build_and_run.bat C:/test/build_and_run.bat

# use pre-installed SDK if available, otherwise compile with mingw
# for CI we'll compile on the host and just copy the exe
COPY test_overflow.exe C:/test/test_overflow.exe

WORKDIR C:/test
CMD ["test_overflow.exe"]
