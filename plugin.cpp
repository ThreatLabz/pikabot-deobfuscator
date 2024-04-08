#include "plugin.hpp"
// Callback for decompiler events. Once the global optimization has finished,
// we attempt to decrypt the strings of the function.  
ssize_t callback(void* ud, hexrays_event_t event, va_list va)
{
	pluginCtx* plugin = (pluginCtx*)ud;
	switch (event)
	{
	case hxe_populating_popup:
	{
		TWidget* widget = va_arg(va, TWidget*);
		TPopupMenu* popup = va_arg(va, TPopupMenu*);
		attach_action_to_popup(widget, popup, "PikabotDeobfuscator::Deobfuscate");
		attach_action_to_popup(widget, popup, "PikabotDeobfuscator::DeobfuscateAll");
	}
	break;
	case hxe_glbopt:
	{
		if (plugin->pluginSingleDecryptActive)
		{
			mba_t* mba = va_arg(va, mba_t*);
			plugin->pluginSingleDecryptActive = false;
			handlers::getAllRC4Keys getRC4Keys;
			mba->for_all_topinsns(getRC4Keys);
			if (getRC4Keys.m_rc4Keys.empty())
				return MERR_OK;
			handlers::DecryptPikabotString visitor(plugin->decrypter, getRC4Keys.m_rc4Keys);
			mba->for_all_topinsns(visitor);
			plugin->m_decryptedStrings = visitor.decryptedStrings;
			msg("[+] Plugin task completed\n");
			return MERR_OK;
		}
	}
	break;
	case hxe_func_printed:
	{
		if (!plugin->m_decryptedStrings.empty() && !plugin->pluginSingleDecryptActive)
		{
			cfunc_t* cfunc = va_arg(va, cfunc_t*);
			for (auto const& [address, decryptedString] : plugin->m_decryptedStrings)
			{
				utils::setDecompilerComment(*cfunc, address, decryptedString);
			}
			plugin->m_decryptedStrings.clear();
			cfunc->save_user_cmts();
			cfunc->refresh_func_ctext();
			return MERR_LOOP;
		}
	}
	break;
	default:
		break;
	}
	return 0;
}

pluginCtx::pluginCtx() : decryptFunctionStringsHandler(this), decryptAllStringsHandler(this)
{
	install_hexrays_callback(callback, this);
	register_action(ACTION_DESC_LITERAL_PLUGMOD(
		"PikabotDeobfuscator::Deobfuscate",
		"Run Pikabot deobfuscator for current function",
		&decryptFunctionStringsHandler,
		this,
		"Ctrl+Shift+F",
		"Deobfuscate Pikabot strings",
		-1));
	register_action(ACTION_DESC_LITERAL_PLUGMOD(
		"PikabotDeobfuscator::DeobfuscateAll",
		"Run Pikabot deobfuscator for all strings",
		&decryptAllStringsHandler,
		this,
		"Ctrl+Shift+A",
		"Deobfuscate all Pikabot strings",
		-1));
}