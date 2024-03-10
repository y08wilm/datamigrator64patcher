/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "patchfinder64.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)

// iOS 8 arm64
int get__MKBDeviceUnlockedSinceBoot_patch_1_ios8(void* kernel_buf,size_t kernel_len) {
    // search 00 94 1A 00 00 14
    // 6a 0e 00 94 1a 00 00 14
    // bl 0x100005aa4
    // b 0x100002168
    // bl 0x1000059f0 -> mov w0, 0x1
    // cbz w0, 0x100002710
    uint8_t search[] = { 0x00, 0x94, 0x1A, 0x00, 0x00, 0x14 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"_MKBDeviceUnlockedSinceBoot\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_MKBDeviceUnlockedSinceBoot\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"_MKBDeviceUnlockedSinceBoot\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"_MKBDeviceUnlockedSinceBoot\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    xref_stuff = xref_stuff + 0x2; // move to b 0x100002168
    xref_stuff = xref_stuff + 0x4; // move to bl 0x1000059f0
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x52800020; // mov w0, #0x1
    return 0;
}

// iOS 8 arm64
int get__MKBDeviceUnlockedSinceBoot_patch_2_ios8(void* kernel_buf,size_t kernel_len) {
    // search 3B 80 52 E4 07 1F 32
    // 42 3B 80 52 E4 07 1F 32
    // mov w2, #0x1da
    // orr w4, wzr, #0x6
    // bl 0x100005a2c
    // bl 0x1000059f0 -> mov w0, 0x1
    // cbnz w0, 0x100003de0
    uint8_t search[] = { 0x3B, 0x80, 0x52, 0xE4, 0x07, 0x1F, 0x32 };
    void* ent_loc = memmem(kernel_buf, kernel_len, search, sizeof(search) / sizeof(*search));
    if (!ent_loc) {
        printf("%s: Could not find \"_MKBDeviceUnlockedSinceBoot\" patch\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_MKBDeviceUnlockedSinceBoot\" patch loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t xref_stuff = (addr_t)GET_OFFSET(kernel_len, ent_loc);
    printf("%s: Found \"_MKBDeviceUnlockedSinceBoot\" xref at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    printf("%s: Patching \"_MKBDeviceUnlockedSinceBoot\" at %p\n\n", __FUNCTION__,(void*)(xref_stuff));
    xref_stuff = xref_stuff + 0x3; // move to orr w4, wzr, #0x6
    xref_stuff = xref_stuff + 0x4; // move to bl 0x100005a2c
    xref_stuff = xref_stuff + 0x4; // move to bl 0x1000059f0
    *(uint32_t *) (kernel_buf + xref_stuff) = 0x52800020; // mov w0, #0x1
    return 0;
}

int main(int argc, char **argv) {
    
    printf("%s: Starting...\n", __FUNCTION__);
    
    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Usage: %s <com.apple.datamigrator_in> <com.apple.datamigrator_out> <args>\n",argv[0]);
        printf("\t-n\t\tPatch _MKBDeviceUnlockedSinceBoot (iOS 8 Only)\n");
        
        return 0;
    }
    
    void* kernel_buf;
    size_t kernel_len;
    
    char *filename = argv[1];
    
    fp = fopen(argv[1], "rb");
    if(!fp) {
        printf("%s: Error opening %s!\n", __FUNCTION__, argv[1]);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    kernel_buf = (void*)malloc(kernel_len);
    if(!kernel_buf) {
        printf("%s: Out of memory!\n", __FUNCTION__);
        fclose(fp);
        return -1;
    }
    
    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);
    
    if(memmem(kernel_buf,kernel_len,"KernelCacheBuilder",18)) {
        printf("%s: Detected IMG4/IM4P, you have to unpack and decompress it!\n",__FUNCTION__);
        return -1;
    }
    
    if (*(uint32_t*)kernel_buf == 0xbebafeca) {
        printf("%s: Detected fat macho kernel\n",__FUNCTION__);
        memmove(kernel_buf,kernel_buf+28,kernel_len);
    }
    
    init_kernel(0, filename);
    
    for(int i=0;i<argc;i++) {
        if(strcmp(argv[i], "-n") == 0) {
            printf("Kernel: Adding _MKBDeviceUnlockedSinceBoot patch...\n");
            get__MKBDeviceUnlockedSinceBoot_patch_1_ios8(kernel_buf,kernel_len);
            get__MKBDeviceUnlockedSinceBoot_patch_2_ios8(kernel_buf,kernel_len);
        }
    }
    
    term_kernel();
    
    /* Write patched kernel */
    printf("%s: Writing out patched file to %s...\n", __FUNCTION__, argv[2]);
    
    fp = fopen(argv[2], "wb+");
    if(!fp) {
        printf("%s: Unable to open %s!\n", __FUNCTION__, argv[2]);
        free(kernel_buf);
        return -1;
    }
    
    fwrite(kernel_buf, 1, kernel_len, fp);
    fflush(fp);
    fclose(fp);
    
    free(kernel_buf);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    
    return 0;
}
