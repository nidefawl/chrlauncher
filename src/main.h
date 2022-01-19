// chrlauncher
// Copyright (c) 2015-2021 Henry++

#pragma once

#include "routine.h"
#include "resource.h"
#include "app.h"

// config
#define LANG_MENU 0

#define CHROMIUM_UPDATE_URL L"https://chromium.woolyss.com/api/v3/?os=windows&bit=%d&type=%s&out=string"

DEFINE_GUID (GUID_TrayIcon, 0xead41630, 0x90bb, 0x4836, 0x82, 0x41, 0xae, 0xae, 0x12, 0xe8, 0x69, 0x12);

typedef struct CMDLINE_OPTS
{
	PR_STRING ini_path;
	PR_STRING optional_argv;
	BOOLEAN is_autodownload;
	BOOLEAN is_bringtofront;
	BOOLEAN is_forcecheck;
	BOOLEAN is_waitdownloadend;
	BOOLEAN is_onlyupdate;
} CMDLINE_OPTS, *PCMDLINE_OPTS;

typedef CONST CMDLINE_OPTS *PCONSTCMDLINE_OPTS;

typedef struct BROWSER_PROCESS_ARGS
{
	// optional_argv
	//
	// Additional arguments provided on command line.
	// Can be URLs or additional switches that will be passed on to the browser process.
	// NULL if none were provided
	PR_STRING optional_argv;

	// browser_arguments
	//
	// Arguments provided from configuration
	// This might include flags like --user-data-dir=...
	PR_STRING browser_arguments;
} BROWSER_PROCESS_ARGS, *PBROWSER_PROCESS_ARGS;

typedef struct BROWSER_INFORMATION
{
	PR_STRING browser_name;
	PR_STRING browser_type;
	PR_STRING cache_path;
	PR_STRING binary_dir;
	PR_STRING binary_path;
	PR_STRING download_url;
	PR_STRING current_version;
	PR_STRING new_version;

	LONG64 timestamp;

	LONG check_period;
	LONG architecture;

	BOOLEAN is_autodownload;
	BOOLEAN is_bringtofront;
	BOOLEAN is_forcecheck;
	BOOLEAN is_waitdownloadend;
	BOOLEAN is_onlyupdate;
} BROWSER_INFORMATION, *PBROWSER_INFORMATION;


typedef struct THREAD_CHECKVERSION_CONTEXT
{
	_Inout_ PBROWSER_INFORMATION pbi;
	_Out_ INT errorcode;
	_Out_ PR_STRING error_context;
} THREAD_CHECKVERSION_CONTEXT, *PTHREAD_CHECKVERSION_CONTEXT;
typedef struct THREAD_UPDATER_CONTEXT
{
	_In_ HWND hwnd;
	_In_ PCONSTCMDLINE_OPTS pcopts;
} THREAD_UPDATER_CONTEXT, *PTHREAD_UPDATER_CONTEXT;

typedef struct THREAD_UPDATER_RESULT
{
	_Out_ BROWSER_INFORMATION updated_bi;
	_Out_ INT errorcode;
	_Out_ INT task_idmsg;
	_Out_ PR_STRING error_context;
} THREAD_UPDATER_RESULT, *PTHREAD_UPDATER_RESULT;


typedef struct APPWINDOW_CONTEXT
{
	PCONSTCMDLINE_OPTS pcopts;
	PBROWSER_INFORMATION pbi;
	PBROWSER_PROCESS_ARGS pba;
	HWND hwnd;
	INT exitcode;
} APPWINDOW_CONTEXT, *PAPPWINDOW_CONTEXT;
