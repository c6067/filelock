#include "filelock.h"



void print_banner(void) {
    printf("\n");
    printf("███████╗██╗██╗     ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗\n");
    printf("██╔════╝██║██║     ██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝\n");
    printf("█████╗  ██║██║     █████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   \n");
    printf("██╔══╝  ██║██║     ██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   \n");
    printf("██║     ██║███████╗███████╗╚██████╗██║  ██║   ██║   ██║        ██║   \n");
    printf("╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   \n");
    printf("\n");
    printf("Simple XOR File Encryption Tool - Educational Purpose Only\n");
    printf("========================================================\n\n");
}


void print_usage(const char* program_name) {
    print_banner();
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Options:\n");
    printf("  -e <directory>    Encrypt all files in directory (current level only)\n");
    printf("  -d <directory>    Decrypt all .crypted files in directory (current level only)\n");
    printf("  -f <file>         Encrypt/decrypt single file\n");
    printf("  -p <password>     Password for encryption/decryption\n");
    printf("  -h                Show this help\n\n");
    printf("Examples:\n");
    printf("  %s -p \"secret123\" -e ./testdir     # Encrypt directory\n", program_name);
    printf("  %s -p \"secret123\" -d ./testdir     # Decrypt directory\n", program_name);
    printf("  %s -p \"secret123\" -f document.txt  # Encrypt single file\n", program_name);
    printf("\n⚠️  WARNING: This tool modifies files permanently!\n");
    printf("   Always backup important files before testing!\n\n");
}


//XOR cipher implementation
void xor_cipher(unsigned char* data, int data_len, const char* key, int key_len) {
    for (int i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}


//Check if file should be processed based on mode
int is_target_file(const char* filepath, int encrypt_mode) {
    char* ext_pos = strstr(filepath, ENCRYPTED_EXT);
    
    if (encrypt_mode) {
        //for encryption: skip already encrypted files
        return (ext_pos == NULL);
    } else {
        //for decryption: only process .crypted files
        return (ext_pos != NULL);
    }
}


int xor_encrypt_file(const char* filepath) {
    FILE* infile = NULL;
    FILE* outfile = NULL;
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    char outpath[MAX_PATH];
    int ret = -1;
    
    //create output filename with .crypted extension
    snprintf(outpath, sizeof(outpath), "%s%s", filepath, ENCRYPTED_EXT);
    
    //open input file
    infile = fopen(filepath, "rb");
    if (!infile) {
        printf("❌ Failed to open: %s\n", filepath);
        return -1;
    }    
    //open output file
    outfile = fopen(outpath, "wb");
    if (!outfile) {
        printf("❌ Failed to create: %s\n", outpath);
        fclose(infile);
        return -1;
    }
    
    //encrypt file in chunks
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, infile)) > 0) {
        xor_cipher(buffer, bytes_read, g_password, g_password_len);
        
        if (fwrite(buffer, 1, bytes_read, outfile) != bytes_read) {
            printf("❌ Write error for: %s\n", outpath);
            goto cleanup;
        }
    }
    
    //success - remove original file
    if (unlink(filepath) == 0) {
        printf("🔒 Encrypted: %s\n", filepath);
        g_file_count++;
        ret = 0;
    } else {
        printf("⚠️  Encrypted but couldn't remove original: %s\n", filepath);
        ret = 0;
    }

cleanup:
    if (infile) fclose(infile);
    if (outfile) fclose(outfile);
    return ret;
}


int xor_decrypt_file(const char* filepath) {
    FILE* infile = NULL;
    FILE* outfile = NULL;
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    char outpath[MAX_PATH];
    char* ext_pos;
    int ret = -1;
    
    //find .crypted extension and create original filename
    ext_pos = strstr(filepath, ENCRYPTED_EXT);
    if (!ext_pos) {
        return 0; //not an encrypted file
    }
    
    //create output filename (remove .crypted extension)
    strncpy(outpath, filepath, ext_pos - filepath);
    outpath[ext_pos - filepath] = '\0';
    
    //open input file
    infile = fopen(filepath, "rb");
    if (!infile) {
        printf("❌ Failed to open: %s\n", filepath);
        return -1;
    }    
    //open output file
    outfile = fopen(outpath, "wb");
    if (!outfile) {
        printf("❌ Failed to create: %s\n", outpath);
        fclose(infile);
        return -1;
    }
    
    //decrypt file in chunks (XOR is symmetric)
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, infile)) > 0) {
        xor_cipher(buffer, bytes_read, g_password, g_password_len);
        
        if (fwrite(buffer, 1, bytes_read, outfile) != bytes_read) {
            printf("❌ Write error for: %s\n", outpath);
            goto cleanup;
        }
    }
    
    //success - remove encrypted file
    if (unlink(filepath) == 0) {
        printf("🔓 Decrypted: %s\n", outpath);
        g_file_count++;
        ret = 0;
    } else {
        printf("⚠️  Decrypted but couldn't remove encrypted file: %s\n", filepath);
        ret = 0;
    }

cleanup:
    if (infile) fclose(infile);
    if (outfile) fclose(outfile);
    return ret;
}


int find_files_recursive_safe(const char* directory, int encrypt_mode, int depth) {
    //check if we've already visited this directory (handles symlink cycles)
    if (is_already_visited(directory)) {
        printf("🔄 Cycle detected, skipping: %s\n", directory);
        return 0;
    }

    DIR* dir;
    struct dirent* entry;
    struct stat file_stat;
    char filepath[MAX_PATH];
    int result = 0;
    
    //DEPTH PROTECTION
    if (depth > MAX_RECURSION_DEPTH) {
        printf("⚠️  Max recursion depth (%d) reached: %s\n", MAX_RECURSION_DEPTH, directory);
        return -1;
    }
    
    dir = opendir(directory);
    if (!dir) {
        printf("❌ Cannot open directory: %s\n", directory);
        return -1;
    }    
    printf("📁 Scanning: %s (depth: %d)\n", directory, depth);
    
    while ((entry = readdir(dir)) != NULL) {
        //skip . and .. 
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }        
        //construct full file path
        snprintf(filepath, sizeof(filepath), "%s/%s", directory, entry->d_name);
        
        //use lstat to get symlink info, not stat(this is very important)
        if (lstat(filepath, &file_stat) != 0) {
            continue;
        }
        
        //SYMLINK PROTECTION - Only recurse into REAL directories
        if (S_ISDIR(file_stat.st_mode) && !S_ISLNK(file_stat.st_mode)) {
            printf("📂 Entering directory: %s (depth: %d)\n", filepath, depth + 1);
            result += find_files_recursive_safe(filepath, encrypt_mode, depth + 1);
        } 
        //handle symlinked directories separately (optional)
        else if (S_ISLNK(file_stat.st_mode)) {
            printf("🔗 Skipping symlink: %s\n", filepath);
        }
        //process regular files
        else if (S_ISREG(file_stat.st_mode)) {
            if (is_target_file(filepath, encrypt_mode)) {
                if (encrypt_mode) {
                    xor_encrypt_file(filepath);
                } else {
                    xor_decrypt_file(filepath);
                }
                result++;
            }
        }
    }
    
    closedir(dir);
    return result;
}

// Wrapper function for easier use
int find_files_recursive(const char* directory, int encrypt_mode) {
    return find_files_recursive_safe(directory, encrypt_mode, 0);
}



int main(int argc, char* argv[]) {
    int opt;
    char* directory = NULL;
    char* single_file = NULL;
    char* password = NULL;
    int encrypt_mode = 0;
    int decrypt_mode = 0;
    
    //parse command line arguments
    while ((opt = getopt(argc, argv, "e:d:f:p:h")) != -1) {
        switch (opt) {
            case 'e':
                encrypt_mode = 1;
                directory = optarg;
                break;
            case 'd':
                decrypt_mode = 1;
                directory = optarg;
                break;
            case 'f':
                single_file = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }
    
    //validate arguments
    if (!password) {
        printf("❌ Error: Password (-p) is required!\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (!directory && !single_file) {
        printf("❌ Error: Must specify directory (-e/-d) or file (-f)!\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (encrypt_mode && decrypt_mode) {
        printf("❌ Error: Cannot use -e and -d together!\n\n");
        return 1;
    }
    
    //setup password
    strncpy(g_password, password, MAX_PASSWORD - 1);
    g_password[MAX_PASSWORD - 1] = '\0';
    g_password_len = strlen(g_password);
    
    if (g_password_len == 0) {
        printf("❌ Error: Password cannot be empty!\n");
        return 1;
    }
    
    print_banner();
    
    //show operation info
    if (encrypt_mode) {
        printf("🔒 ENCRYPTION MODE\n");
        printf("Target: %s\n", directory ? directory : single_file);
        printf("Password: %s\n", password);
        printf("Action: Files will be encrypted and renamed with .crypted extension\n\n");
    } else if (decrypt_mode) {
        printf("🔓 DECRYPTION MODE\n");
        printf("Target: %s\n", directory ? directory : single_file);
        printf("Password: %s\n", password);
        printf("Action: .crypted files will be decrypted and restored\n\n");
    } else {
        //single file mode - determine operation by extension
        if (strstr(single_file, ENCRYPTED_EXT)) {
            printf("🔓 DECRYPTION MODE (Single File)\n");
            decrypt_mode = 1;
        } else {
            printf("🔒 ENCRYPTION MODE (Single File)\n");
            encrypt_mode = 1;
        }
        printf("Target: %s\n", single_file);
        printf("Password: %s\n\n", password);
    }
    
    printf("⚠️  WARNING: This will permanently modify files!\n");
    printf("Press Enter to continue or Ctrl+C to cancel...\n");
    getchar();
    
    printf("\n🚀 Starting operation...\n\n");
    
    //execute operation
    if (single_file) {
        // Process single file
        if (encrypt_mode) {
            if (xor_encrypt_file(single_file) == 0) {
                g_file_count = 1;
            }
        } else {
            if (xor_decrypt_file(single_file) == 0) {
                g_file_count = 1;
            }
        }
    } else if (directory) {
        // Process directory with recursion
        find_files_recursive(directory, encrypt_mode);
    }
    
    //show results
    printf("\n" "✅ Operation completed!\n");
    printf("Files processed: %d\n", g_file_count);
    
    if (encrypt_mode) {
        printf("\n💀 Your files have been encrypted!\n");
        printf("🔑 Use the same password with -d option to decrypt them.\n");
        printf("📝 Keep your password safe - without it, files cannot be recovered!\n");
    } else {
        printf("\n🎉 Your files have been restored!\n");
    }
    
    return 0;
}
