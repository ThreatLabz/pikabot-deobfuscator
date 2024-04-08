#pragma once
#define VERSION "0.1"
struct pluginCtx;

#include "decrypter.hpp"
#include "handlers.hpp"


// Callback for decompiler events. Once the global optimization has finished,
// we attempt to decrypt the strings of the function.  
ssize_t callback(void* ud, hexrays_event_t event, va_list va);

// Action handler for decrypting all strings in current function.
struct decryptFunctionStrsHandler : public action_handler_t
{
	pluginCtx* pluginModule;
	decryptFunctionStrsHandler(pluginCtx* _plugmod) : pluginModule(_plugmod) {}
	virtual int activate(action_activation_ctx_t* ctx) override;
	virtual action_state_t update(action_update_ctx_t*) override
	{
		return AST_ENABLE;
	};
};

// Action handler for decrypting all strings in all identified functions.
struct decryptAllHandler : public action_handler_t
{
	pluginCtx* pluginModule;
	decryptAllHandler(pluginCtx* _plugmod) : pluginModule(_plugmod) {}
	virtual int activate(action_activation_ctx_t* ctx) override;
	virtual action_state_t update(action_update_ctx_t*) override
	{
		return AST_ENABLE;
	};
};

// Initialize plugin context
struct pluginCtx : public plugmod_t
{
	decryptFunctionStrsHandler decryptFunctionStringsHandler;
	decryptAllHandler decryptAllStringsHandler;
	bool pluginSingleDecryptActive = false;
	std::map<unsigned int, std::string> m_decryptedStrings;
	Decrypter decrypter;
	pluginCtx();
	~pluginCtx() { term_hexrays_plugin();}
	virtual bool idaapi run(size_t arg) override { return true; };
};