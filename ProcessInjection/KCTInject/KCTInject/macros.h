#pragma once

#define ok(msg, ...) printf("\t[+] " msg "\n", ##__VA_ARGS__);
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__);
#define error(msg, ...) printf("\t[-] " msg "\n", ##__VA_ARGS__);