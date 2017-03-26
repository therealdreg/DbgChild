#include "plugin.h"

static duint cbExpr(int argc, duint* argv, void* userdata)
{
    if(argc < 2)
        return 0;
    return argv[0] + argv[1];
}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    if(!_plugin_registerexprfunction(pluginHandle, PLUGIN_NAME, 2, cbExpr, nullptr))
        _plugin_logputs("[" PLUGIN_NAME "] Error registering the \"" PLUGIN_NAME "\" expression function!");
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here (clearing menus optional).
bool pluginStop()
{
    return true;
}

//Do GUI/Menu related things here.
void pluginSetup()
{
}
