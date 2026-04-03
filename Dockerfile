FROM mcr.microsoft.com/windows/servercore:ltsc2022
COPY test_overflow.exe C:/test/test_overflow.exe
WORKDIR C:/test
CMD ["test_overflow.exe"]
