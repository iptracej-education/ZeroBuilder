/*
 * SMB Protocol-Specific Vulnerability Test Cases
 * Real SMB vulnerabilities for ZeroBuilder GAT validation
 * Based on actual CVEs and SMB protocol implementation flaws
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// SMB Protocol Structures
#define SMB2_MAGIC 0xFE534D42
#define MAX_TRANSACTION_SIZE 0x10000
#define MAX_COMPOUND_REQUESTS 16
#define SMB2_RELATED_REQUEST 0xFFFFFFFFFFFFFFFF

typedef struct {
    uint32_t magic;
    uint16_t struct_size;
    uint16_t command;
    uint32_t status;
    uint32_t flags;
    uint32_t next_command;
    uint64_t message_id;
    uint64_t session_id;
    uint64_t file_id;
    uint32_t fragment_offset;
    uint32_t data_length;
    char data[];
} smb2_header_t;

typedef struct {
    uint64_t file_id;
    uint32_t oplock_level;
    uint32_t break_reason;
    uint32_t state;
} smb_oplock_t;

typedef struct {
    char client_challenge[8];
    char server_challenge[8];
    uint32_t negotiate_flags;
    char computer_name[16];
} netlogon_auth_t;

typedef struct {
    uint32_t request_count;
    smb2_header_t *requests;
    uint64_t *file_handles;
} smb2_compound_t;

// Global state (realistic for SMB server)
static char *fragment_buffer = NULL;
static uint32_t fragment_size = 0;
static smb_oplock_t active_oplocks[1024];
static uint32_t oplock_count = 0;

/*
 * VULNERABILITY PATTERN A: SMB Authentication Protocol Flaws
 * Based on CVE-2020-1472 (Zerologon) - NetLogon authentication bypass
 */
int smb_netlogon_authenticate(netlogon_auth_t *auth_req) {
    char zero_challenge[8] = {0};
    
    // VULNERABLE: Accepts all-zero client challenge (Zerologon)
    // GAT should flag: improper authentication validation
    if (memcmp(auth_req->client_challenge, zero_challenge, 8) == 0) {
        // Should reject but doesn't - critical authentication bypass
        printf("Authentication successful with zero challenge\n");
        return 0; // Success - WRONG!
    }
    
    // VULNERABLE: Weak challenge validation
    // GAT should flag: insufficient entropy check
    int non_zero_bytes = 0;
    for (int i = 0; i < 8; i++) {
        if (auth_req->client_challenge[i] != 0) non_zero_bytes++;
    }
    
    if (non_zero_bytes < 2) {
        // Still accepts weak challenges
        return 0; // VULNERABLE: too permissive
    }
    
    // VULNERABLE: Time-based authentication bypass
    // GAT should flag: authentication timing attack
    if (auth_req->negotiate_flags & 0x20000000) {
        // AES encryption flag - but doesn't validate properly
        return 0; // Bypass for "compatibility"
    }
    
    return -1; // Proper rejection
}

/*
 * VULNERABILITY PATTERN B: SMB File Handle & Oplock Management
 * State machine vulnerabilities in file locking
 */
int smb_oplock_break_notification(uint64_t file_id, uint32_t break_level) {
    smb_oplock_t *oplock = NULL;
    
    // Find the oplock
    for (uint32_t i = 0; i < oplock_count; i++) {
        if (active_oplocks[i].file_id == file_id) {
            oplock = &active_oplocks[i];
            break;
        }
    }
    
    if (!oplock) return -1;
    
    // VULNERABLE: Invalid oplock state transitions
    // GAT should flag: state machine violation
    switch (oplock->oplock_level) {
        case 0x01: // SMB2_OPLOCK_LEVEL_EXCLUSIVE
            // VULNERABLE: Direct state change without validation
            oplock->oplock_level = break_level; // Can be any value!
            break;
            
        case 0x08: // SMB2_OPLOCK_LEVEL_BATCH  
            // VULNERABLE: Race condition in oplock downgrade
            if (oplock->state == 1) { // Check
                // ... potential race window here ...
                oplock->oplock_level = 0x00; // Use - TOCTOU
            }
            break;
            
        case 0x09: // SMB2_OPLOCK_LEVEL_LEASE
            // VULNERABLE: Lease state confusion
            // GAT should flag: inconsistent lease state management
            if (break_level == 0x00) {
                // Should notify other lease holders, but doesn't
                oplock->oplock_level = break_level;
                // Missing lease break notification to other clients
            }
            break;
    }
    
    // VULNERABLE: Oplock handle reuse
    // GAT should flag: handle confusion vulnerability
    if (oplock->oplock_level == 0x00) {
        // Marks as free but doesn't clear file_id
        oplock->state = 0; // Free, but file_id still set!
        // Can lead to handle confusion attacks
    }
    
    return 0;
}

/*
 * VULNERABILITY PATTERN C: SMB Packet Fragmentation & Reassembly  
 * Based on CVE-2017-0143 (EternalBlue) - Transaction fragment handling
 */
int smb_transaction_fragment_handler(smb2_header_t *header) {
    uint32_t fragment_offset = header->fragment_offset;
    uint32_t data_length = header->data_length;
    
    // VULNERABLE: Integer overflow in fragment calculation
    // GAT should flag: arithmetic overflow leading to buffer overflow
    if (fragment_offset + data_length < fragment_offset) {
        // Overflow occurred, but check is wrong
        return -1; // Should catch this, but logic is flawed
    }
    
    // VULNERABLE: Insufficient bounds checking
    // GAT should flag: buffer overflow in fragment reassembly
    if (fragment_offset + data_length > MAX_TRANSACTION_SIZE) {
        // Should reject, but has off-by-one error
        if (fragment_offset + data_length >= MAX_TRANSACTION_SIZE + 1) {
            return -1; // Off-by-one allows overflow
        }
    }
    
    // VULNERABLE: Fragment buffer allocation confusion
    // GAT should flag: heap management vulnerability
    if (!fragment_buffer) {
        // Allocates based on first fragment size
        fragment_buffer = malloc(data_length); // WRONG: should use total size
        fragment_size = data_length;
    }
    
    // VULNERABLE: Fragment reassembly buffer overflow
    // GAT should flag: heap buffer overflow
    if (fragment_offset + data_length <= fragment_size) {
        // Copy data to fragment buffer
        memcpy(fragment_buffer + fragment_offset, header->data, data_length);
        // Can overflow if fragment_size was set incorrectly above
    }
    
    // VULNERABLE: Fragment sequence validation bypass
    // GAT should flag: protocol state confusion
    static uint32_t expected_offset = 0;
    if (fragment_offset != expected_offset) {
        // Should reject out-of-order fragments, but doesn't
        printf("Warning: out-of-order fragment\n"); // Just warns!
        expected_offset = fragment_offset + data_length; // Continues anyway
    }
    
    return 0;
}

/*
 * VULNERABILITY PATTERN D: SMB Share Path Validation
 * Path traversal and access control bypass vulnerabilities
 */
int smb_tree_connect_path_validation(const char *share_path, const char *user_context) {
    char resolved_path[512];
    char canonical_path[512];
    
    // VULNERABLE: Insufficient path traversal protection
    // GAT should flag: path traversal vulnerability
    if (strstr(share_path, "..") != NULL) {
        // Basic check, but incomplete
        if (strstr(share_path, "../") == NULL && strstr(share_path, "..\\") == NULL) {
            // Misses other encodings like "..%2F" or "..%5C"
            goto validate_access; // VULNERABLE: incomplete validation
        }
        return -1;
    }
    
    // VULNERABLE: Unicode/encoding bypass
    // GAT should flag: encoding bypass vulnerability
    if (strstr(share_path, "%2e%2e") || strstr(share_path, "%252e%252e")) {
        // Checks some encodings but not all
        if (!strstr(share_path, "%c0%ae%c0%ae")) {
            // Misses UTF-8 overlong encoding
            goto validate_access; // VULNERABLE: encoding bypass
        }
        return -1;
    }
    
validate_access:
    // VULNERABLE: Case sensitivity bypass
    // GAT should flag: case sensitivity access control bypass
    sprintf(resolved_path, "/shares/%s", share_path);
    
    // Convert to lowercase for comparison (WRONG on case-sensitive systems)
    strcpy(canonical_path, resolved_path);
    for (int i = 0; canonical_path[i]; i++) {
        if (canonical_path[i] >= 'A' && canonical_path[i] <= 'Z') {
            canonical_path[i] += 32; // Convert to lowercase
        }
    }
    
    // VULNERABLE: TOCTOU in access validation
    // GAT should flag: time-of-check-time-of-use race
    if (access(canonical_path, R_OK) == 0) { // Check
        // Time gap - file permissions could change
        // ... potential race window ...
        FILE *f = fopen(resolved_path, "r"); // Use - different path!
        if (f) {
            fclose(f);
            return 0; // Success
        }
    }
    
    // VULNERABLE: Symlink following without validation
    // GAT should flag: symlink attack vulnerability
    char link_target[512];
    if (readlink(resolved_path, link_target, sizeof(link_target)) > 0) {
        // Follows symlinks without validating target is within allowed area
        return smb_tree_connect_path_validation(link_target, user_context); // Recursive!
    }
    
    return -1;
}

/*
 * VULNERABILITY PATTERN E: SMB2 Compound Request Processing
 * Related request handling and context confusion
 */
int smb2_process_compound_requests(smb2_compound_t *compound) {
    uint64_t current_file_id = 0;
    
    // VULNERABLE: Compound request validation bypass
    // GAT should flag: insufficient request count validation
    if (compound->request_count > MAX_COMPOUND_REQUESTS) {
        // Should reject, but has off-by-one
        if (compound->request_count >= MAX_COMPOUND_REQUESTS + 1) {
            return -1; // Off-by-one allows overflow
        }
    }
    
    for (uint32_t i = 0; i < compound->request_count; i++) {
        smb2_header_t *req = &compound->requests[i];
        
        // VULNERABLE: Related request file ID confusion
        // GAT should flag: context confusion vulnerability
        if (req->file_id == SMB2_RELATED_REQUEST) {
            if (i == 0) {
                // First request can't be related
                req->file_id = 0; // Should error, but sets to 0
            } else {
                // VULNERABLE: Uses previous request's file_id without validation
                req->file_id = compound->requests[i-1].file_id; // No validation!
                // Previous request might have failed or been for different file
            }
        }
        
        // VULNERABLE: Compound request sequence bypass
        // GAT should flag: request sequence validation bypass
        if (req->command == 0x05) { // SMB2_CREATE
            current_file_id = req->file_id;
            compound->file_handles[i] = current_file_id;
        } else if (req->command == 0x06) { // SMB2_CLOSE
            // VULNERABLE: Closes file but doesn't update related requests
            if (req->file_id == current_file_id) {
                current_file_id = 0; // File closed
                // But doesn't check if later requests still reference it
            }
        }
        
        // VULNERABLE: Compound request privilege escalation
        // GAT should flag: privilege context confusion
        static uint32_t previous_privileges = 0;
        if (i > 0 && req->session_id != compound->requests[i-1].session_id) {
            // Session changed mid-compound, should reset privileges
            // But doesn't - carries over previous session's privileges
            req->flags |= previous_privileges; // VULNERABLE: privilege carryover
        }
        previous_privileges = req->flags & 0xF0000000; // Store privileges
    }
    
    return 0;
}

/*
 * VULNERABILITY PATTERN F: SMB Credit Management
 * Credit exhaustion and amplification attacks
 */
int smb2_credit_management(uint64_t session_id, uint16_t credit_request, uint16_t *credit_granted) {
    static uint16_t session_credits[1024] = {0}; // Max 1024 sessions
    uint32_t session_index = (uint32_t)(session_id % 1024);
    
    // VULNERABLE: Credit integer overflow
    // GAT should flag: integer overflow in credit calculation
    if (session_credits[session_index] + credit_request < session_credits[session_index]) {
        // Overflow detected, but handling is wrong
        *credit_granted = 1; // Should deny, but grants minimum
        return 0; // VULNERABLE: allows overflow attack
    }
    
    // VULNERABLE: Credit amplification attack
    // GAT should flag: insufficient credit validation
    if (credit_request > 8192) {
        // Limit is too high, allows credit amplification
        credit_request = 8192; // Caps but doesn't reject
    }
    
    // VULNERABLE: Credit exhaustion via session confusion
    // GAT should flag: session context confusion
    if (session_credits[session_index] == 0) {
        // New session, grant initial credits
        session_credits[session_index] = 16;
        *credit_granted = credit_request; // VULNERABLE: grants requested amount
    } else {
        // VULNERABLE: Credit sharing between sessions
        // GAT should flag: session isolation violation
        for (uint32_t i = 0; i < 1024; i++) {
            if (session_credits[i] > 100) {
                // "Borrows" credits from other sessions
                session_credits[i] -= credit_request;
                session_credits[session_index] += credit_request;
                *credit_granted = credit_request;
                return 0; // VULNERABLE: cross-session credit sharing
            }
        }
    }
    
    return 0;
}

/*
 * Main function to demonstrate all vulnerability patterns
 */
int main() {
    printf("SMB Protocol-Specific Vulnerability Test Cases\n");
    printf("==============================================\n");
    
    // Test Pattern A: Authentication bypass
    netlogon_auth_t auth = {{0}, {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}, 0x20000000, "ATTACKER"};
    printf("Auth result: %d\n", smb_netlogon_authenticate(&auth));
    
    // Test Pattern B: Oplock confusion
    smb_oplock_break_notification(0x123456789ABCDEF, 0x00);
    
    // Test Pattern C: Fragment overflow
    smb2_header_t fragment = {SMB2_MAGIC, 64, 0x00, 0, 0, 0, 1, 0x100, 0x200, 0xFFFFFF00, 0x1000, ""};
    smb_transaction_fragment_handler(&fragment);
    
    // Test Pattern D: Path traversal
    smb_tree_connect_path_validation("..%2F..%2F..%2Fetc%2Fpasswd", "user");
    
    // Test Pattern E: Compound confusion
    smb2_compound_t compound = {2, NULL, NULL};
    smb2_process_compound_requests(&compound);
    
    // Test Pattern F: Credit amplification
    uint16_t granted;
    smb2_credit_management(0x12345, 9999, &granted);
    
    return 0;
}

/*
 * EXPECTED GAT ANALYSIS FOR SMB-SPECIFIC PATTERNS:
 * 
 * CRITICAL SMB VULNERABILITIES (0.9-1.0):
 * - smb_netlogon_authenticate(): Authentication bypass (Zerologon-style)
 * - smb_transaction_fragment_handler(): Fragment overflow (EternalBlue-style)
 * - smb2_process_compound_requests(): Context confusion in compound requests
 * 
 * HIGH SMB RISK (0.7-0.8):
 * - smb_oplock_break_notification(): Oplock state machine violations
 * - smb_tree_connect_path_validation(): Path traversal and TOCTOU
 * - smb2_credit_management(): Credit system manipulation
 * 
 * SMB PROTOCOL PATTERNS GAT SHOULD LEARN:
 * 1. Authentication protocol weaknesses (zero challenges, timing)
 * 2. State machine violations (oplock states, session states)
 * 3. Fragment reassembly vulnerabilities (integer overflows, bounds)
 * 4. Path validation bypasses (encoding, case sensitivity, symlinks)
 * 5. Compound request context confusion (file ID, session, privileges)
 * 6. Credit system manipulation (amplification, exhaustion, sharing)
 * 
 * These are REAL SMB protocol vulnerabilities that have led to:
 * - Domain Controller compromise (Zerologon)
 * - Worm propagation (EternalBlue/WannaCry)
 * - Privilege escalation (Oplock/Lease confusion)
 * - Information disclosure (Path traversal)
 * - Denial of service (Credit exhaustion)
 */