/*#########################################################################
# * @author     zhouwg2000@gmail.com
# * @date    	2015-10  ~ present
# * @note
# * @history
# *             2015-10, create
#
#	Copyright (C) zhou.weiguo, 2015-2021  All rights reserved.
#
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *      http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
#
#########################################################################
*/
#include "cde_log.h"
#ifndef __KERNEL__
#include <string.h>
#endif

//http://www.cnblogs.com/clover-toeic/p/4031618.html

#define NONE                 "\e[0m"
#define BLACK                "\e[0;30m"
#define L_BLACK              "\e[1;30m"
#define RED                  "\e[0;31m"
#define L_RED                "\e[1;31m"
#define GREEN                "\e[0;32m"
#define L_GREEN              "\e[1;32m"
#define BROWN                "\e[0;33m"
#define L_YELLOW             "\e[1;33m"
#define BLUE                 "\e[0;34m"
#define L_BLUE               "\e[1;34m"
#define PURPLE               "\e[0;35m"
#define L_PURPLE             "\e[1;35m"
#define CYAN                 "\e[0;36m"
#define L_CYAN               "\e[1;36m"
#define WHITE                "\e[0;37m"
#define L_WHITE              "\e[1;37m"
#define BOLD                 "\e[1m"
#define UNDERLINE            "\e[4m"
#define BLINK                "\e[5m"
#define REVERSE              "\e[7m"
#define HIDE                 "\e[8m"
#define CLEAR                "\e[2J"
#define CLRLINE              "\r\e[K" //or "\e[1K\r"

#ifndef __cplusplus
#define true 1
#define false 0
#endif

#define LOG_BUF_LEN 4096

#if (defined __ANDROID__) || (defined ANDROID)
extern  int __android_log_print(int prio, const char *tag,  const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__ ((format(printf, 3, 4)))
#endif
;
#endif

int  validateLogLevel(int prio);
void setGlobalLogLevel(int level);

static char logBuf[LOG_BUF_LEN];
static int gAllowedLogEnabled   = 1;
static int gAllowedLogLevel     = CDE_LOG_DEFAULT;

typedef struct {
    const char *szModuleName;
    int bModuleEnabled;
    const char *szFileName;
    int bFileEnabled;
}MODULE_LOG_PROP;

//developer could modify this array to disable/enable module's log output
//we should group some source file into a standalone module
//need sanity check with gLogPropConfs to keep consistency
static MODULE_LOG_PROP gLogPropConfs[] = {
    {"ijkplayer", true, "ijkplayer.c", true},
    {"live555", true, "DynamicRTSPServer.cpp", true},
};


void setGlobalLogEnabled(int bEnable) {
    if (bEnable) {
        gAllowedLogEnabled = 1;
    } else {
        gAllowedLogEnabled = 0;
    }
}


void  setGlobalLogModule(const char *moduleName, int bEnabled) {
    size_t logPropCounts = sizeof(gLogPropConfs) / sizeof(MODULE_LOG_PROP);

    if (NULL == moduleName)
        return;

    size_t i = 0;
    for (i = 0; i < logPropCounts; i++) {
        if (gLogPropConfs[i].szModuleName != NULL) {
            if (0 == memcmp(moduleName, gLogPropConfs[i].szModuleName, strlen(gLogPropConfs[i].szModuleName))) {
                gLogPropConfs[i].bModuleEnabled = bEnabled;
                break;
            }
        }
    }
}


void setGlobalLogLevel(int level) {
    gAllowedLogLevel = (level >= 0 ? level : CDE_LOG_SILENT);
}


int validateLogLevel(int prio) {
    return (prio >= gAllowedLogLevel);
}


#ifdef __KERNEL__
asmlinkage void  LOG_PRI_ORIG_IMPL(const char *file, const char *func, unsigned int line,  int priority, const char *tag, const char *format,  ...) {
#else
void  LOG_PRI_ORIG_IMPL(const char *file, const char *func, unsigned int line,  int priority, const char *tag, const char *format,  ...) {
#endif
    //filtering step-1
    if (0 == gAllowedLogEnabled) {
        return;
    }


    //filtering step-2
    if (!validateLogLevel(priority)) {
        return;
    }

    int bOutput = false; //filtering step-3, setting bOutput to false manually before filtering by modulename and filename
    size_t logPropCounts = sizeof(gLogPropConfs) / sizeof(MODULE_LOG_PROP);
    size_t i = 0;
    for (i = 0; i < logPropCounts; i++) {
        if ((NULL != gLogPropConfs[i].szModuleName) &&  (0 == memcmp("ijkplayer", gLogPropConfs[i].szModuleName, strlen(gLogPropConfs[i].szModuleName)))) {
            bOutput = true; 
            //greenlight for ijkplayer, should we save log to local file or upload to remote loggerServer?
            break;
        }

        //make memcmp happy otherwise segment fault
        if (NULL == tag) {
            break;
        }

        if ((NULL != gLogPropConfs[i].szModuleName) &&  (0 == memcmp(tag, gLogPropConfs[i].szModuleName, strlen(gLogPropConfs[i].szModuleName)))) {
            if (!gLogPropConfs[i].bModuleEnabled) {
                break;
            }

            if ((NULL != gLogPropConfs[i].szFileName) &&  (NULL != strstr(file, gLogPropConfs[i].szFileName))) {
                if (gLogPropConfs[i].bFileEnabled) {
                    bOutput = true;
                }
                break;
            }
        }
    }

    //filtering ok
    if (bOutput && gAllowedLogEnabled) {
        memset(logBuf, 0, LOG_BUF_LEN);

        va_list va;
        va_start(va, format);
        int len_prefix  = 0;
        int len_content = 0;
        const char *color = L_WHITE;

        switch (priority) {
            case CDE_LOG_VERBOSE:
                color = L_PURPLE;
                break;
            case CDE_LOG_DEBUG:
                color = L_YELLOW;
                break;
            case CDE_LOG_INFO:
                color = L_GREEN;
                break;
            case CDE_LOG_WARN:
                color = RED;
                break;
            case CDE_LOG_ERROR:
                color = L_RED;
                break;
            default:
                color = L_WHITE;
                break;
        }

        if (NULL == tag) {
            tag = " ";
        }

#ifndef __KERNEL__
        len_prefix = snprintf(logBuf, LOG_BUF_LEN, "%s[%s, %s, %d]: ", color, file, func, line);
#else
        len_prefix = snprintf(logBuf, LOG_BUF_LEN, "[%s, %s, %d]: ",  file, func, line);
#endif
        len_content = vsnprintf(logBuf + len_prefix, LOG_BUF_LEN - len_prefix, format, va);
        snprintf(logBuf + len_prefix + len_content, LOG_BUF_LEN - len_prefix - len_content, "\n");

#ifndef __KERNEL__
        #if (defined __ANDROID__) || (defined ANDROID)
        __android_log_print(priority, tag, "%s", logBuf);
        __android_log_print(priority, tag, NONE);
        #else
        printf("%s%s", logBuf, NONE);
        #endif
#else
        printk(KERN_INFO "%s", logBuf);
#endif
        va_end(va);
    }
}


#ifdef __KERNEL__
EXPORT_SYMBOL_GPL(LOG_PRI_ORIG_IMPL);
#endif
