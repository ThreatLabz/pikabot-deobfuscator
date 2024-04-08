#include "plugin.hpp"

int idaapi decryptFunctionStrsHandler::activate(action_activation_ctx_t* ctx)
{
	vdui_t* vdui = get_widget_vdui(ctx->widget);
	if (vdui != nullptr)
	{
		if (!handlers::extractAESInfo(pluginModule))
			return 0;
		pluginModule->pluginSingleDecryptActive = true;
		vdui->refresh_view(true);
		return 1;
	}
	return 0;
}

int idaapi decryptAllHandler::activate(action_activation_ctx_t* ctx)
{
	vdui_t* vdui = get_widget_vdui(ctx->widget);
	if (vdui != nullptr)
	{
		if (!handlers::extractAESInfo(pluginModule))
			return 0;
		handlers::decryptAllStrings(pluginModule);
		vdui->refresh_view(true);
		return 1;
	}
	return 0;
}

static plugmod_t* idaapi init()
{
	if (!init_hexrays_plugin())
	{
		error("[-] Decompiler plugin not found\n");
		return PLUGIN_SKIP;
	}
	msg("[+] Pikabot deobfuscator (v%s) initialized\n", VERSION);
	pluginCtx* plugmod = new pluginCtx;
	return plugmod;
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE | PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  "PikabotDeobfuscator",
  nullptr
};