#include <dlfcn.h>
#include <android/log.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

#include "plthook.h"

#define LOG_TAG "ZTZWASHERE"

static ssize_t my_strcmp(const char *s1, const char *s2) 
{
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "my_strcmp called with %s and %s", s1, s2);
    return strcmp(s1, s2);
}

__attribute__((constructor))
void init() 
{
    void *handle = NULL;
    do 
    {
        handle = dlopen("libFreakyFrida.so", RTLD_LAZY);
        if (!handle) 
        {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to dlopen libFreakyFrida.so: %s", dlerror());
        }
    } while (0);

    void* strcmp_addr = dlsym(handle, "strcmp");
    if (!strcmp_addr) 
    {
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to dlsym strcmp");
        return;
    }

    plthook_t *plthook;
    if (plthook_open(&plthook, "libFreakyFrida.so") != 0) {
        printf("plthook_open error: %s\n", plthook_error());
        return;
    }

    if (plthook_replace(plthook, "strcmp", (void*)my_strcmp, NULL) != 0) {
        printf("plthook_replace error: %s\n", plthook_error());
        plthook_close(plthook);
        return;
    }
    plthook_close(plthook);
}
