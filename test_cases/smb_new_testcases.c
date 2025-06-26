SMB Test Cases for ZeroBuilder
Test Case 1: SMBv1 Packet Parser
File: smb_v1_packet_parser.c
CVE: CVE-2017-0143 (EternalBlue)
Vulnerability: Buffer Overflow in Packet Parsing
Description: Simulates a buffer overflow due to lack of bounds checking in SMBv1 packet parsing, as exploited in EternalBlue.
Source Code:
c

Collapse

Wrap

Copy
#include <string.h>
void smb_v1_parse_packet(char *packet, int len) {
    char buffer[128];
    // Vulnerable: No bounds check
    memcpy(buffer, packet, len);  // Buffer overflow (EternalBlue)
    if (strncmp(buffer, "SMB1", 4) == 0) {
        // Process SMBv1 negotiate request
    }
}
Test Case 2: SMBv3 Compression Handler
File: smb_v3_compression.c
CVE: CVE-2020-0796 (SMBGhost)
Vulnerability: Out-of-Bounds Write in Compression
Description: Mimics an out-of-bounds write in SMBv3 compression handling, as seen in SMBGhost, due to improper length validation.
Source Code:
c

Collapse

Wrap

Copy
#include <stdlib.h>
void smb_v3_decompress(char *compressed, int len) {
    char *decompressed = malloc(256);
    if (!decompressed) return;
    // Vulnerable: No bounds check on len
    memcpy(decompressed, compressed, len);  // Out-of-bounds write (SMBGhost)
    if (strncmp(decompressed, "COMPRESSED", 10) == 0) {
        // Process SMBv3 compressed packet
    }
    free(decompressed);
}
Test Case 3: SMB Session Setup
File: smb_session_auth.c
CVE: CVE-2025-33073 (NTLM Reflection)
Vulnerability: Weak Authentication
Description: Represents a weak authentication check that bypasses SMB signing, enabling NTLM relay attacks.
Source Code:
c

Collapse

Wrap

Copy
#include <string.h>
int smb_session_auth(char *credentials, int len) {
    char auth_token[64];
    // Vulnerable: No signing check
    memcpy(auth_token, credentials, len > 64 ? 64 : len);  // No null termination
    if (strncmp(auth_token, "NTLM", 4) == 0) {
        return 1;  // Auth bypass (NTLM reflection)
    }
    return 0;
}
Test Case 4: SMBv2 Negotiate Response
File: smb_v2_negotiate.c
CVE: CVE-2008-4835 (MS09-050)
Vulnerability: Buffer Overflow in Negotiation
Description: Simulates a buffer overflow in SMBv2 negotiation due to insufficient packet validation.
Source Code:
c

Collapse

Wrap

Copy
#include <string.h>
void smb_v2_negotiate(char *request, int len) {
    char response[96];
    // Vulnerable: No bounds check
    memcpy(response, request, len);  // Buffer overflow (MS09-050)
    if (strncmp(response, "NEGOTIATE_V2", 12) == 0) {
        // Process SMBv2 negotiate
    }
}
Test Case 5: SMB Client Session
File: smb_client_session.c
CVE: CVE-2010-0020 (MS10-006)
Vulnerability: DoS via Malicious Server Response
Description: Models a client-side DoS vulnerability caused by an unvalidated server response in session negotiation.
Source Code:
c

Collapse

Wrap

Copy
#include <stdlib.h>
void smb_client_negotiate(char *server_response) {
    char *session = malloc(64);
    if (!session) return;
    // Vulnerable: No response validation
    strcpy(session, server_response);  // DoS (MS10-006)
    if (strncmp(session, "SERVER_OK", 9) == 0) {
        // Establish client session
    }
    free(session);
}
Test Case 6: SMB Null Session
File: smb_null_session.c
CVE: CVE-1999-0519
Vulnerability: Unauthenticated Access
Description: Allows unauthenticated access to SMB resources by accepting null or empty user credentials.
Source Code:
c

Collapse

Wrap

Copy
#include <string.h>
int smb_null_session(char *user) {
    // Vulnerable: No auth check
    if (user == NULL || strlen(user) == 0) {
        return 1;  // Grant access (null session)
    }
    return 0;
}
Test Case 7: SMB Session State Mismanagement
File: smb_session_state.c
CVE: CVE-2025-38051
Vulnerability: Use-After-Free
Description: Triggers a use-after-free by accessing freed session data during SMB session processing.
Source Code:
c

Collapse

Wrap

Copy
#include <stdlib.h>
#include <string.h>
void smb_session_process(char *packet) {
    char *session_data = malloc(128);
    if (!session_data) return;
    strcpy(session_data, packet);
    if (strncmp(session_data, "SESSION", 7) == 0) {
        free(session_data);
        // Vulnerable: Use-after-free
        session_data[0] = 'S';  // UAF (CVE-2025-38051)
    } else {
        free(session_data);
    }
}
Test Case 8: SMBv3 Encryption Handler
File: smb_v3_encryption.c
CVE: CVE-2025-37750
Vulnerability: Use-After-Free in Decryption
Description: Simulates a use-after-free in concurrent SMBv3 decryption, as seen in multichannel decryption flaws.
Source Code:
c

Collapse

Wrap

Copy
#include <stdlib.h>
void smb_v3_decrypt(char *encrypted, int len) {
    char *decrypted = malloc(len);
    if (!decrypted) return;
    memcpy(decrypted, encrypted, len);
    free(decrypted);
    // Vulnerable: UAF in concurrent decryption
    decrypted[0] = encrypted[0];  // UAF (CVE-2025-37750)
}
Test Case 9: SMB Multi-Message Packet Sequence
File: smb_multi_packet.c
CVE: CVE-2009-0949
Vulnerability: Integer Overflow
Description: Causes an integer overflow and buffer overflow by mishandling multi-message packet lengths.
Source Code:
c

Collapse

Wrap

Copy
#include <string.h>
void smb_multi_packet(char *packets[], int count) {
    char buffer[256];
    int total_len = 0;
    // Vulnerable: Integer overflow
    for (int i = 0; i < count; i++) {
        total_len += strlen(packets[i]);
        if (total_len > 256) total_len = 256;
        strcat(buffer, packets[i]);  // Buffer overflow (CVE-2009-0949)
    }
    if (strncmp(buffer, "MULTI", 5) == 0) {
        // Process multi-message
    }
}
Test Case 10: SMB Information Disclosure
File: smb_info_leak.c
CVE: CVE-2025-29956
Vulnerability: Buffer Over-Read
Description: Triggers a buffer over-read in SMB response processing, leaking sensitive memory.
Source Code:
c

Collapse

Wrap

Copy
#include <string.h>
void smb_process_response(char *response, int len) {
    char buffer[64];
    // Vulnerable: Over-read
    memcpy(buffer, response, len + 8);  // Buffer over-read (CVE-2025-29956)
    if (strncmp(buffer, "RESPONSE", 8) == 0) {
        // Process response
    }
}
Test Case 11: SMB Client File URL
File: smb_client_file_url.c
CVE: CVE-2025-5986
Vulnerability: Malicious File URL Processing
Description: Processes unvalidated file:// URLs in SMB client, potentially leaking credentials or executing code.
Source Code:
c

Collapse

Wrap

Copy
#include <string.h>
void smb_client_process_url(char *url) {
    char path[128];
    // Vulnerable: No URL validation
    strcpy(path, url);  // Processes file:// URLs (CVE-2025-5986)
    if (strncmp(path, "file://", 7) == 0) {
        // Access SMB share
    }
}
Test Case 12: SMBv2 Negotiation Downgrade
File: smb_v2_downgrade.c
CVE: CVE-2016-2110
Vulnerability: Protocol Downgrade
Description: Forces a downgrade to vulnerable SMBv1 by accepting unvalidated negotiation responses.
Source Code:
c

Collapse

Wrap

Copy
#include <string.h>
void smb_v2_negotiate_downgrade(char *request) {
    char response[64];
    // Vulnerable: No version validation
    strcpy(response, request);  // Forces SMBv1 fallback (CVE-2016-2110)
    if (strncmp(response, "SMB1", 4) == 0) {
        // Downgrade to SMBv1
    }
}

Test Case 13: SMB Session Concurrent UAF
File: smb_session_concurrent_uaf.c
CVE: CVE-2025-37899
Vulnerability: Use-After-Free in Concurrent Session Access
Description: Simulates the CVE-2025-37899 vulnerability where concurrent threads access freed session user data during SMB2 LOGOFF processing.
Source Code:
c

Collapse

Wrap

Copy
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

struct smb_session {
    struct smb_user *user;
    int active;
    pthread_mutex_t lock;
};

struct smb_user {
    char username[64];
    int uid;
};

void ksmbd_free_user(struct smb_user *user) {
    if (user) {
        memset(user, 0, sizeof(*user));
        free(user);
    }
}

// Vulnerable SMB2 LOGOFF handler
void smb2_logoff_handler(struct smb_session *sess) {
    // Missing proper synchronization
    if (sess->user) {
        ksmbd_free_user(sess->user);  // Thread 1 frees user
        sess->user = NULL;            // Clears the field
    }
}

// Concurrent access from another connection
void smb_session_access(struct smb_session *sess) {
    // Vulnerable: Access after free in concurrent thread
    if (sess->user) {
        // Thread 2 may access freed memory here
        strncpy(sess->user->username, "ACCESSED", 8);  // UAF (CVE-2025-37899)
    }
}

// Test scenario demonstrating the race condition
void test_concurrent_session_uaf() {
    struct smb_session *sess = malloc(sizeof(*sess));
    sess->user = malloc(sizeof(struct smb_user));
    strcpy(sess->user->username, "testuser");
    sess->user->uid = 1000;
    sess->active = 1;
    
    // Simulated concurrent access scenario
    // Thread 1 would call smb2_logoff_handler()
    // Thread 2 would call smb_session_access()
    // No synchronization between threads leads to UAF
    
    free(sess->user);
    free(sess);
}