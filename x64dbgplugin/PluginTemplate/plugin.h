#pragma once

#include "pluginmain.h"

//plugin data
#define PLUGIN_NAME "dbgchildprocess"
#define PLUGIN_VERSION 1

void GetPIDFromUserDialogW(wchar_t * out_pid_str);
//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
bool pluginStop();
void pluginSetup();
