#include <dlfcn.h>
#include <android/log.h>
#include <stdio.h>

#define LOG_TAG "ZTZWASHERE"

typedef unsigned long long (*get_flag_t)(int, int);

__attribute__((constructor))
void init() 
{
    void *handle = NULL;
    do 
    {
        handle = dlopen("libRudefrida.so", RTLD_NOLOAD);
        if (!handle) 
        {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to dlopen libRudefrida.so: %s", dlerror());
            break;
        }
    } while (0);

    get_flag_t get_flag = (get_flag_t)dlsym(handle, "_Z8get_flagii");
    if (!get_flag) 
    {
        get_flag_t get_flag = (get_flag_t)((unsigned long long)handle + 0x00000000000618E0);
        if (!get_flag) 
        {
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, "Failed to dlsym get_flag");
            return;
        }
    }

    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "Calling get_flag...");

    unsigned long long res = get_flag(1000, 337);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "get_flag returned: 0x%llx", res);
}
