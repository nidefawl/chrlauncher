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

typedef struct BROWSER_INFORMATION
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
	BOOLEAN is_onlyupdate;
	BOOLEAN is_waitdownloadend;
} BROWSER_INFORMATION, *PBROWSER_INFORMATION;
