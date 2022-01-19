// chrlauncher
// Copyright (c) 2015-2021 Henry++

#include "routine.h"

#include "main.h"
#include "rapp.h"

#include "CpuArch.h"

#include "7z.h"
#include "7zAlloc.h"
#include "7zBuf.h"
#include "7zCrc.h"
#include "7zFile.h"
#include "7zVersion.h"

#include "miniz.h"

#include "resource.h"


#define APP_WM_FROMTHREAD           (WM_APP + 20)

#define IDM_TASK_FETCH_VERSION      2
#define IDM_TASK_DOWNLOAD           3
#define IDM_TASK_INSTALLATION       4
#define IDM_TASK_BROWSER_RUNNING    5
#define IDM_TASK_UP_TO_DATE         6

R_QUEUED_LOCK lock_download = PR_QUEUED_LOCK_INIT;
R_QUEUED_LOCK lock_thread = PR_QUEUED_LOCK_INIT;

R_WORKQUEUE workqueue;


/*
BOOL CALLBACK activate_browser_window_callback (_In_ HWND hwnd, _In_ LPARAM lparam)
{
	PBROWSER_INFORMATION pbi;
	WCHAR path[1024];
	ULONG pid;
	ULONG length;
	HANDLE hproc;

	GetWindowThreadProcessId (hwnd, &pid);

	if (HandleToUlong (NtCurrentProcessId ()) == pid)
		return TRUE;

	if (!_r_wnd_isvisible (hwnd))
		return TRUE;

	hproc = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

	if (!_r_fs_isvalidhandle (hproc))
		return TRUE;

	pbi = (PBROWSER_INFORMATION)lparam;

	length = RTL_NUMBER_OF (path);

	QueryFullProcessImageName (hproc, 0, path, &length);

	CloseHandle (hproc);

	if (_r_str_isequal2 (&pbi->binary_path->sr, path, TRUE))
	{
		_r_wnd_toggle (hwnd, TRUE);
		return FALSE;
	}

	return TRUE;
}

FORCEINLINE VOID activate_browser_window (_In_ PBROWSER_INFORMATION pbi)
{
	EnumWindows (&activate_browser_window_callback, (LPARAM)pbi);
}

BOOLEAN path_is_url (_In_ LPCWSTR path)
{
	if (PathMatchSpec (path, L"*.ini"))
		return FALSE;

	if (PathIsURL (path) || PathIsHTMLFile (path))
		return TRUE;

	static LPCWSTR types[] = {
		L"application/pdf",
		L"image/svg+xml",
		L"image/webp",
		L"text/html",
	};

	for (SIZE_T i = 0; i < RTL_NUMBER_OF (types); i++)
	{
		if (PathIsContentType (path, types[i]))
			return TRUE;
	}

	return FALSE;
}
*/

VOID update_browser_info (_In_ HWND hwnd, _In_ PBROWSER_INFORMATION pbi)
{
	PR_STRING date_dormat;
	PR_STRING localized_string = NULL;
	R_STRINGREF empty_string;

	_r_obj_initializestringrefconst (&empty_string, _r_locale_getstring (IDS_STATUS_NOTFOUND));

	date_dormat = _r_format_unixtime_ex (pbi->timestamp, FDTF_SHORTDATE | FDTF_SHORTTIME);

	_r_obj_movereference (&localized_string, _r_format_string (L"%s:", _r_locale_getstring (IDS_BROWSER)));
	_r_ctrl_settablestring (hwnd, IDC_BROWSER, &localized_string->sr, IDC_BROWSER_DATA, pbi->browser_name ? &pbi->browser_name->sr : &empty_string);

	_r_obj_movereference (&localized_string, _r_format_string (L"%s:", _r_locale_getstring (IDS_CURRENTVERSION)));
	_r_ctrl_settablestring (hwnd, IDC_CURRENTVERSION, &localized_string->sr, IDC_CURRENTVERSION_DATA, pbi->current_version ? &pbi->current_version->sr : &empty_string);

	_r_obj_movereference (&localized_string, _r_format_string (L"%s:", _r_locale_getstring (IDS_VERSION)));
	_r_ctrl_settablestring (hwnd, IDC_VERSION, &localized_string->sr, IDC_VERSION_DATA, pbi->new_version ? &pbi->new_version->sr : &empty_string);

	_r_obj_movereference (&localized_string, _r_format_string (L"%s:", _r_locale_getstring (IDS_DATE)));
	_r_ctrl_settablestring (hwnd, IDC_DATE, &localized_string->sr, IDC_DATE_DATA, date_dormat ? &date_dormat->sr : &empty_string);

	if (date_dormat)
		_r_obj_dereference (date_dormat);

	if (localized_string)
		_r_obj_dereference (localized_string);
}

// init_browser_info

// - set browser process args from command line options and config
VOID init_browser_args (_Inout_ PBROWSER_PROCESS_ARGS pba, _In_ PCONSTCMDLINE_OPTS pcopts)
{
	PR_STRING browser_arguments = _r_config_getstringexpand (L"ChromiumCommandLine", L"--user-data-dir=..\\profile --no-default-browser-check");

	pba->browser_arguments = NULL;

	if (browser_arguments)
		_r_obj_movereference (&pba->browser_arguments, browser_arguments);

	pba->optional_argv = pcopts->optional_argv;

}

// init_browser_info

// - checks config settings
// - retrieves current version from .exe
VOID init_browser_info (_Inout_ PBROWSER_INFORMATION pbi, _In_ PCONSTCMDLINE_OPTS pcopts)
{
	static R_STRINGREF bin_names[] = {
		PR_STRINGREF_INIT (L"brave.exe"),
		PR_STRINGREF_INIT (L"firefox.exe"),
		PR_STRINGREF_INIT (L"basilisk.exe"),
		PR_STRINGREF_INIT (L"palemoon.exe"),
		PR_STRINGREF_INIT (L"waterfox.exe"),
		PR_STRINGREF_INIT (L"dragon.exe"),
		PR_STRINGREF_INIT (L"iridium.exe"),
		PR_STRINGREF_INIT (L"iron.exe"),
		PR_STRINGREF_INIT (L"opera.exe"),
		PR_STRINGREF_INIT (L"slimjet.exe"),
		PR_STRINGREF_INIT (L"vivaldi.exe"),
		PR_STRINGREF_INIT (L"chromium.exe"),
		PR_STRINGREF_INIT (L"chrome.exe"), // default
	};

	static R_STRINGREF separator_sr = PR_STRINGREF_INIT (L"\\");


	//copy cmd line args
	pbi->is_autodownload = pcopts->is_autodownload;
	pbi->is_bringtofront = pcopts->is_bringtofront;
	pbi->is_forcecheck = pcopts->is_forcecheck;
	pbi->is_waitdownloadend = pcopts->is_waitdownloadend;
	pbi->is_onlyupdate = pcopts->is_onlyupdate;

	// Configure paths
	PR_STRING binary_dir;
	PR_STRING binary_name;
	PR_STRING string;

	binary_dir = _r_config_getstringexpand (L"ChromiumDirectory", L".\\bin");
	binary_name = _r_config_getstring (L"ChromiumBinary", L"chrome.exe");

	_r_obj_movereference (&pbi->binary_dir, binary_dir);
	_r_str_trimstring2 (pbi->binary_dir, L"\\", 0);

	string = _r_path_search (pbi->binary_dir->buffer);

	if (string)
		_r_obj_movereference (&pbi->binary_dir, string);

	_r_obj_movereference (&pbi->binary_path, _r_obj_concatstringrefs (3, &pbi->binary_dir->sr, &separator_sr, &binary_name->sr));

	if (!_r_fs_exists (pbi->binary_path->buffer))
	{
		for (SIZE_T i = 0; i < RTL_NUMBER_OF (bin_names); i++)
		{
			_r_obj_movereference (&pbi->binary_path, _r_obj_concatstringrefs (3, &pbi->binary_dir->sr, &separator_sr, &bin_names[i]));

			if (_r_fs_exists (pbi->binary_path->buffer))
				break;
		}

		if (_r_obj_isstringempty (pbi->binary_path) || !_r_fs_exists (pbi->binary_path->buffer))
			_r_obj_movereference (&pbi->binary_path, _r_obj_concatstringrefs (3, &pbi->binary_dir->sr, &separator_sr, &binary_name->sr)); // fallback (use defaults)
	}

	_r_obj_dereference (binary_name);

	_r_obj_movereference (&pbi->cache_path, _r_format_string (
		L"%s\\%s_%" TEXT (PR_ULONG) L".bin",
		_r_sys_gettempdirectory ()->buffer,
		_r_app_getnameshort (),
		_r_str_gethash2 (pbi->binary_path,
		TRUE
	)));

	// Get browser architecture
	pbi->architecture = _r_config_getlong (L"ChromiumArchitecture", 64);

	if (pbi->architecture != 64 && pbi->architecture != 32)
	{
		pbi->architecture = 0;

		// ...by executable
		if (_r_fs_exists (pbi->binary_path->buffer))
		{
			ULONG binary_type;

			if (GetBinaryType (pbi->binary_path->buffer, &binary_type))
			{
				pbi->architecture = (binary_type == SCS_64BIT_BINARY) ? 64 : 32;
			}
		}

		// ...by processor architecture
		if (!pbi->architecture)
		{
			SYSTEM_INFO si = {0};
			GetNativeSystemInfo (&si);

			pbi->architecture = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? 64 : 32;
		}
	}

	if (pbi->architecture != 32 && pbi->architecture != 64)
		pbi->architecture = 64; // default architecture

	PR_STRING browser_type = _r_config_getstring (L"ChromiumType", L"dev-codecs-sync");

	if (browser_type)
		_r_obj_movereference (&pbi->browser_type, browser_type);



	_r_obj_movereference (&pbi->browser_name, _r_format_string (L"%s (%" PR_LONG L"-bit)", pbi->browser_type->buffer, pbi->architecture));
	_r_obj_movereference (&pbi->current_version, _r_res_queryversionstring (pbi->binary_path->buffer));


	pbi->check_period = _r_config_getlong (L"ChromiumCheckPeriod", 2);

	if (pbi->check_period == -1)
		pbi->is_forcecheck = TRUE;

	// set default config
	if (!pbi->is_autodownload)
		pbi->is_autodownload = _r_config_getboolean (L"ChromiumAutoDownload", FALSE);

	if (!pbi->is_bringtofront)
		pbi->is_bringtofront = _r_config_getboolean (L"ChromiumBringToFront", TRUE);

	if (!pbi->is_waitdownloadend)
		pbi->is_waitdownloadend = _r_config_getboolean (L"ChromiumWaitForDownloadEnd", TRUE);

	if (!pbi->is_onlyupdate)
		pbi->is_onlyupdate = _r_config_getboolean (L"ChromiumUpdateOnly", FALSE);

	// rewrite options when update-only mode is enabled
	if (pbi->is_onlyupdate)
	{
		pbi->is_forcecheck = TRUE;
		pbi->is_bringtofront = TRUE;
		pbi->is_waitdownloadend = TRUE;
	}
}

VOID _app_setstatus (_In_ HWND hwnd, _In_opt_ LPCWSTR text, _In_opt_ ULONG64 v, _In_opt_ ULONG64 t)
{
	//clean this up
	LONG64 percent = 0;

	if (!v && t)
	{
		_r_status_settextformat (hwnd, IDC_STATUSBAR, 0, L"%s 0%%", text);

		if (!_r_str_isempty (text))
		{
			_r_tray_setinfoformat (hwnd, &GUID_TrayIcon, NULL, L"%s\r\n%s: 0%%", _r_app_getname (), text);
		}
		else
		{
			_r_tray_setinfo (hwnd, &GUID_TrayIcon, NULL, _r_app_getname ());
		}
	}
	else if (v && t)
	{
		percent = _r_calc_clamp64 (_r_calc_percentof64 (v, t), 0, 100);

		_r_status_settextformat (hwnd, IDC_STATUSBAR, 0, L"%s %" PR_LONG64 L"%%", text, percent);

		if (!_r_str_isempty (text))
		{
			_r_tray_setinfoformat (hwnd, &GUID_TrayIcon, NULL, L"%s\r\n%s: %" PR_LONG64 L"%%", _r_app_getname (), text, percent);
		}
		else
		{
			_r_tray_setinfo (hwnd, &GUID_TrayIcon, NULL, _r_app_getname ());
		}
	}
	else
	{
		_r_status_settext (hwnd, IDC_STATUSBAR, 0, text);

		if (!_r_str_isempty (text))
		{
			_r_tray_setinfoformat (hwnd, &GUID_TrayIcon, NULL, L"%s\r\n%s", _r_app_getname (), text);
		}
		else
		{
			_r_tray_setinfo (hwnd, &GUID_TrayIcon, NULL, _r_app_getname ());
		}
	}

	SendDlgItemMessage (hwnd, IDC_PROGRESS, PBM_SETPOS, (WPARAM)(LONG)percent, 0);
}

VOID _app_cleanupoldbinary (_In_ PBROWSER_INFORMATION pbi)
{
	WIN32_FIND_DATA wfd;
	PR_STRING path;
	HANDLE hfile;

	if (!pbi->binary_dir)
		return;

	// remove old binary directory
	// https://github.com/henrypp/chrlauncher/issues/180

	path = _r_obj_concatstrings (2, pbi->binary_dir->buffer, L"\\*");

	hfile = FindFirstFile (path->buffer, &wfd);

	if (_r_fs_isvalidhandle (hfile))
	{
		do
		{
			if ((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
				continue;

			if (wfd.cFileName[0] == L'.')
				continue;

			_r_obj_movereference (&path, _r_obj_concatstrings (3, pbi->binary_dir->buffer, L"\\", wfd.cFileName));

			_r_fs_deletedirectory (path->buffer, TRUE);
		}
		while (FindNextFile (hfile, &wfd));

		FindClose (hfile);
	}

	_r_obj_dereference (path);
}

VOID _app_cleanupoldmanifest (_In_ PBROWSER_INFORMATION pbi)
{
	WIN32_FIND_DATA wfd;
	PR_STRING path;
	HANDLE hfile;

	if (!pbi->binary_dir || !pbi->current_version)
		return;

	path = _r_obj_concatstrings (2, pbi->binary_dir->buffer, L"\\*.manifest");

	hfile = FindFirstFile (path->buffer, &wfd);

	if (_r_fs_isvalidhandle (hfile))
	{
		do
		{
			if (_r_str_isstartswith2 (&pbi->current_version->sr, wfd.cFileName, TRUE))
			{
				_r_obj_movereference (&path, _r_obj_concatstrings (3, pbi->binary_dir->buffer, L"\\", wfd.cFileName));

				_r_fs_deletefile (path->buffer, 0);
			}
		}
		while (FindNextFile (hfile, &wfd));

		FindClose (hfile);
	}

	_r_obj_dereference (path);
}

BOOLEAN _app_browserisrunning (_In_ PBROWSER_INFORMATION pbi)
{
	HANDLE hfile;

	hfile = CreateFile (pbi->binary_path->buffer, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	DWORD lasterror = GetLastError ();

	if (hfile)
	{
		CloseHandle (hfile);
	}


	return lasterror == ERROR_SHARING_VIOLATION;
}

INT _app_startbrowser (_In_ PBROWSER_INFORMATION pbi, _In_ PBROWSER_PROCESS_ARGS pba, _Out_opt_ PR_STRING* browser_cmdline_inspect)
{
	PR_STRING args;
	PR_STRING commandline;
	INT errorcode;

	if (browser_cmdline_inspect)
		*browser_cmdline_inspect = NULL;

	if (_r_obj_isstringempty (pbi->binary_path) || !_r_fs_exists (pbi->binary_path->buffer))
		return ERROR_FILE_NOT_FOUND;


	// combine the 3 parts together

	//  <browser_arguments> + " " + <optional_argv>
	args = _r_obj_concatstrings (3, _r_obj_getstring (pba->browser_arguments),
									((pba->browser_arguments && pba->optional_argv) ? L" " : NULL),
									_r_obj_getstring (pba->optional_argv));

	//  <binary_path> + " " + <browser_arguments> + " " + <optional_argv>
	BOOLEAN b = (_r_obj_isstringempty (args));
	commandline = _r_obj_concatstrings (5, L"\"", pbi->binary_path->buffer, L"\"",
										   (_r_obj_isstringempty(args) ? NULL : L" "),
										   _r_obj_getstring(args));

	_r_log (LOG_LEVEL_DEBUG, &GUID_TrayIcon, L"_app_openbrowser::commandline", 0, commandline->buffer);

	STARTUPINFO startup_info = {0};
	startup_info.cb = sizeof (startup_info);
	startup_info.dwFlags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;

	errorcode = _r_sys_createprocess_ex (
		pbi->binary_path->buffer,
		commandline->buffer,
		pbi->binary_dir->buffer,
		NULL,
		SW_SHOWDEFAULT,
		0);

	if (args)
		_r_obj_dereference (args);

	if (commandline)
	{
		if (browser_cmdline_inspect)
			*browser_cmdline_inspect = commandline;
		else
			_r_obj_dereference (commandline);
	}


	return errorcode;
}

INT _app_startbrowser_safe (_In_ PBROWSER_INFORMATION pbi, _In_ PBROWSER_PROCESS_ARGS pba, _In_opt_ HWND hwnd)
{
	PR_STRING browser_cmdline_inspect = {0};
	INT errorcode = _app_startbrowser (pbi, pba, &browser_cmdline_inspect);
	if (errorcode && hwnd)
		_r_show_errormessage_ex (hwnd, _r_locale_getstring (IDS_STATUS_ERROR_RUN_PROCESS), errorcode, NULL, browser_cmdline_inspect);
	if (!errorcode && hwnd)
		SetProp (hwnd, L"browser_started", (PVOID)1);
	if (browser_cmdline_inspect)
		_r_obj_dereference (browser_cmdline_inspect);
	return errorcode;
}

BOOLEAN _app_ishaveupdate (_In_ PBROWSER_INFORMATION pbi)
{
	return !_r_obj_isstringempty (pbi->download_url) && !_r_obj_isstringempty (pbi->new_version);
}

BOOLEAN _app_isupdatedownloaded (_In_ PBROWSER_INFORMATION pbi)
{
	return !_r_obj_isstringempty (pbi->cache_path) && _r_fs_exists (pbi->cache_path->buffer);
}

BOOLEAN _app_need_fetch_remote_version (_In_ PBROWSER_INFORMATION pbi)
{
	if (pbi->is_forcecheck)
		return TRUE;

	if (pbi->check_period && ((_r_unixtime_now () - _r_config_getlong64 (L"ChromiumLastCheck", 0)) >= _r_calc_days2seconds (pbi->check_period)))
		return TRUE;

	return FALSE;
}

BOOLEAN _app_is_local_version_outdated (_In_ PBROWSER_INFORMATION pbi)
{
	if (_r_obj_isstringempty(pbi->current_version))
		return TRUE;
	return (pbi->new_version && _r_str_versioncompare (&pbi->current_version->sr, &pbi->new_version->sr) == -1);
}

UINT _app_getactionid (_In_ PBROWSER_INFORMATION pbi)
{
	if (_app_is_local_version_outdated (pbi))
	{
		if (_app_isupdatedownloaded (pbi))
			return IDS_ACTION_INSTALL;

		if (_app_ishaveupdate (pbi))
			return IDS_ACTION_DOWNLOAD;
	}

	return IDS_ACTION_CHECK;
}

INT _app_fetch_version_info_from_url (_Inout_ PBROWSER_INFORMATION pbi, _Out_ PR_STRING* purl)
{
	assert (purl);

	R_DOWNLOAD_INFO download_info;
	PR_STRING update_url;
	PR_STRING url;
	INT errorcode = ERROR_SUCCESS;
	PR_HASHTABLE result = NULL;

	*purl = NULL;

	update_url = _r_config_getstring (L"ChromiumUpdateUrl", CHROMIUM_UPDATE_URL);

	if (!update_url)
	{
		return ERROR_INVALID_PARAMETER;
	}

	url = _r_format_string (update_url->buffer, pbi->architecture, pbi->browser_type->buffer);
	*purl = url;

	_r_obj_dereference (update_url);


	if (_r_obj_isstringempty (url))
	{
		return ERROR_INVALID_PARAMETER;
	}

	HINTERNET hsession;
	PR_STRING string;
	ULONG code;

	hsession = _r_inet_createsession (_r_app_getuseragent ());

	if (!hsession)
	{
		return (INT) GetLastError ();
	}
	_r_inet_initializedownload (&download_info);

	code = _r_inet_begindownload (hsession, url, &download_info);

	if (code != ERROR_SUCCESS)
	{
		_r_log (LOG_LEVEL_ERROR, &GUID_TrayIcon, TEXT (__FUNCTION__), code, url->buffer);

		return code;

	}
	string = download_info.u.string;

	if (_r_obj_isstringempty (string))
	{
		_r_log (LOG_LEVEL_ERROR, &GUID_TrayIcon, TEXT (__FUNCTION__), code, url->buffer);
		return ERROR_INVALID_DATA;
	}

	result = _r_str_unserialize (&string->sr, L';', L'=');

	if (_r_obj_ishashtableempty (result))
	{
		_r_log (LOG_LEVEL_ERROR, &GUID_TrayIcon, TEXT (__FUNCTION__), code, url->buffer);
		return ERROR_INVALID_DATA;
	}

	_r_inet_destroydownload (&download_info);

	_r_inet_close (hsession);

	if (!purl)
		_r_obj_dereference (url);

	if (!_r_obj_ishashtableempty (result))
	{
		PR_STRING value_string;

		value_string = _r_obj_findhashtablepointer (result, _r_str_gethash (L"download", TRUE));
		if (!value_string)
			return ERROR_INVALID_DATA;

		_r_obj_movereference (&pbi->download_url, value_string);

		value_string = _r_obj_findhashtablepointer (result, _r_str_gethash (L"version", TRUE));
		if (!value_string)
			return ERROR_INVALID_DATA;

		_r_obj_movereference (&pbi->new_version, value_string);

		value_string = _r_obj_findhashtablepointer (result, _r_str_gethash (L"timestamp", TRUE));
		if (!value_string)
			return ERROR_INVALID_DATA;

		pbi->timestamp = _r_str_tolong64 (&value_string->sr);

		_r_obj_dereference (value_string);

		return 0;
	}
	return ERROR_INVALID_DATA;
}


BOOLEAN WINAPI _app_downloadupdate_callback (_In_ ULONG total_written, _In_ ULONG total_length, _In_opt_ PVOID ctxt)
{
	PTHREAD_UPDATER_CONTEXT pupdatercontext = (PTHREAD_UPDATER_CONTEXT)ctxt;
	if (pupdatercontext)
		_app_setstatus (pupdatercontext->hwnd, _r_locale_getstring (IDS_STATUS_DOWNLOAD), total_written, total_length);

	return TRUE;
}
VOID _app_extractupdate_callback (_In_ ULONG64 total_written, _In_ ULONG64 total_length, _In_opt_ PVOID ctxt)
{
	PTHREAD_UPDATER_CONTEXT pupdatercontext = (PTHREAD_UPDATER_CONTEXT)ctxt;
	if (pupdatercontext)
		_app_setstatus (pupdatercontext->hwnd, _r_locale_getstring (IDS_STATUS_INSTALL), total_written, total_length);
}

INT _app_downloadupdate (_In_ PVOID ctx, _In_ PBROWSER_INFORMATION pbi)
{
	if (_app_isupdatedownloaded (pbi))
		return 0;

	PR_STRING temp_file;
	HINTERNET hsession;
	HANDLE hfile;
	INT errorcode = 0;

	temp_file = _r_obj_concatstrings (2, pbi->cache_path->buffer, L".tmp");

	//_r_fs_deletefile (pbi->cache_path->buffer, TRUE);

	_r_queuedlock_acquireshared (&lock_download);

	hsession = _r_inet_createsession (_r_app_getuseragent ());

	if (hsession)
	{
		hfile = CreateFile (temp_file->buffer, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (!_r_fs_isvalidhandle (hfile))
		{
			errorcode = (INT) GetLastError ();
			_r_log (LOG_LEVEL_ERROR, &GUID_TrayIcon, L"CreateFile", errorcode, temp_file->buffer);
		}
		else
		{
			R_DOWNLOAD_INFO download_info;

			_r_inet_initializedownload_ex (&download_info, hfile, &_app_downloadupdate_callback, ctx);

			errorcode = _r_inet_begindownload (hsession, pbi->download_url, &download_info);

			_r_inet_destroydownload (&download_info); // required!

			if (!errorcode)
			{
				SAFE_DELETE_REFERENCE (pbi->download_url); // clear download url

				_r_fs_movefile (temp_file->buffer, pbi->cache_path->buffer, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);
			}
			else
			{
				_r_log (LOG_LEVEL_ERROR, &GUID_TrayIcon, TEXT (__FUNCTION__), errorcode, pbi->download_url->buffer);

				//_r_fs_deletefile (pbi->cache_path->buffer, TRUE);

			}

			_r_fs_deletefile (temp_file->buffer, TRUE);
		}

		_r_inet_close (hsession);
	}

	_r_queuedlock_releaseshared (&lock_download);

	_r_obj_dereference (temp_file);


	return errorcode;
}

BOOLEAN _app_unpack_7zip (_In_ PVOID ctx, _In_ PBROWSER_INFORMATION pbi, _In_ PR_STRINGREF bin_name)
{
#define kInputBufSize ((SIZE_T)1 << 18)

	static const ISzAlloc g_Alloc = {SzAlloc, SzFree};

	BOOLEAN result = FALSE;

	ISzAlloc alloc_imp = g_Alloc;
	ISzAlloc alloc_temp_imp = g_Alloc;

	CFileInStream archive_stream;
	CLookToRead2 look_stream;
	CSzArEx db;
	UInt16 *temp_buff = NULL;
	SIZE_T temp_size = 0;

	SRes code = InFile_OpenW (&archive_stream.file, pbi->cache_path->buffer);

	if (code != ERROR_SUCCESS)
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"InFile_OpenW", code, pbi->cache_path->buffer);
		return FALSE;
	}

	FileInStream_CreateVTable (&archive_stream);
	LookToRead2_CreateVTable (&look_stream, 0);

	look_stream.buf = (byte *)ISzAlloc_Alloc (&alloc_imp, kInputBufSize);

	if (!look_stream.buf)
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"ISzAlloc_Alloc", SZ_ERROR_MEM, NULL);
	}
	else
	{
		look_stream.bufSize = kInputBufSize;
		look_stream.realStream = &archive_stream.vt;
		LookToRead2_Init (&look_stream);

		CrcGenerateTable ();

		SzArEx_Init (&db);

		code = SzArEx_Open (&db, &look_stream.vt, &alloc_imp, &alloc_temp_imp);

		if (code != SZ_OK)
		{
			_r_log (LOG_LEVEL_ERROR, NULL, L"SzArEx_Open", code, pbi->cache_path->buffer);
		}
		else
		{
			// if you need cache, use these 3 variables.
			// if you use external function, you can make these variable as static.

			UInt32 block_index = UINT32_MAX; // it can have any value before first call (if out_buffer = 0)
			Byte *out_buffer = NULL; // it must be 0 before first call for each new archive.
			size_t out_buffer_size = 0; // it can have any value before first call (if out_buffer = 0)

			R_STRINGREF separator_sr = PR_STRINGREF_INIT (L"\\");
			R_STRINGREF path;
			PR_STRING root_dir_name = NULL;

			UInt64 total_size = 0;
			UInt64 total_read = 0;
			SIZE_T length;

			// find root directory which contains main executable
			for (UInt32 i = 0; i < db.NumFiles; i++)
			{
				if (SzArEx_IsDir (&db, i))
					continue;

				length = SzArEx_GetFileNameUtf16 (&db, i, NULL);
				total_size += SzArEx_GetFileSize (&db, i);

				if (length > temp_size)
				{
					temp_size = length;

					if (temp_buff)
					{
						temp_buff = _r_mem_reallocatezero (temp_buff, temp_size * sizeof (UInt16));
					}
					else
					{
						temp_buff = _r_mem_allocatezero (temp_size * sizeof (UInt16));
					}
				}

				if (!root_dir_name)
				{
					length = SzArEx_GetFileNameUtf16 (&db, i, temp_buff);

					if (!length)
						continue;

					_r_obj_initializestringref_ex (&path, (LPWSTR)temp_buff, (length - 1) * sizeof (WCHAR));

					_r_str_replacechar (&path, L'/', OBJ_NAME_PATH_SEPARATOR);

					length = path.length - bin_name->length - separator_sr.length;

					if (_r_str_isendsswith (&path, bin_name, TRUE) && path.buffer[length / sizeof (WCHAR)] == OBJ_NAME_PATH_SEPARATOR)
					{
						_r_obj_movereference (&root_dir_name, _r_obj_createstring_ex (path.buffer, path.length - bin_name->length));

						_r_str_trimstring (root_dir_name, &separator_sr, 0);
					}
				}
			}

			for (UInt32 i = 0; i < db.NumFiles; i++)
			{
				length = SzArEx_GetFileNameUtf16 (&db, i, temp_buff);

				if (!length)
					continue;

				_r_obj_initializestringref_ex (&path, (LPWSTR)temp_buff, (length - 1) * sizeof (WCHAR));

				_r_str_replacechar (&path, L'/', OBJ_NAME_PATH_SEPARATOR);
				_r_str_trimstringref (&path, &separator_sr, 0);

				// skip non-root dirs
				if (!_r_obj_isstringempty (root_dir_name) && (path.length <= root_dir_name->length || !_r_str_isstartswith (&path, &root_dir_name->sr, TRUE)))
					continue;

				CSzFile out_file;
				PR_STRING dest_path;

				if (root_dir_name)
					_r_obj_skipstringlength (&path, root_dir_name->length + separator_sr.length);

				dest_path = _r_obj_concatstringrefs (3, &pbi->binary_dir->sr, &separator_sr, &path);

				if (SzArEx_IsDir (&db, i))
				{
					_r_fs_mkdir (dest_path->buffer);
				}
				else
				{
					total_read += SzArEx_GetFileSize (&db, i);

					_app_extractupdate_callback (total_read, total_size, ctx);

					// create directory if not-exist
					{
						PR_STRING sub_dir = _r_path_getbasedirectory (&dest_path->sr);

						if (sub_dir)
						{
							if (!_r_fs_exists (sub_dir->buffer))
								_r_fs_mkdir (sub_dir->buffer);

							_r_obj_dereference (sub_dir);
						}
					}

					size_t offset = 0;
					size_t out_size_processed = 0;

					code = SzArEx_Extract (&db, &look_stream.vt, i, &block_index, &out_buffer, &out_buffer_size, &offset, &out_size_processed, &alloc_imp, &alloc_temp_imp);

					if (code != SZ_OK)
					{
						_r_log (LOG_LEVEL_ERROR, NULL, L"SzArEx_Extract", code, dest_path->buffer);
					}
					else
					{
						code = OutFile_OpenW (&out_file, dest_path->buffer);

						if (code != SZ_OK)
						{
							_r_log (LOG_LEVEL_ERROR, NULL, L"OutFile_OpenW", code, dest_path->buffer);
						}
						else
						{
							SIZE_T processed_size = out_size_processed;

							code = File_Write (&out_file, out_buffer + offset, &processed_size);

							if (code != SZ_OK || processed_size != out_size_processed)
							{
								_r_log (LOG_LEVEL_ERROR, NULL, L"File_Write", code, dest_path->buffer);
							}
							else
							{
								if (SzBitWithVals_Check (&db.Attribs, i))
								{
									UInt32 attrib = db.Attribs.Vals[i];

									//	p7zip stores posix attributes in high 16 bits and adds 0x8000 as marker.
									//	We remove posix bits, if we detect posix mode field

									if ((attrib & 0xF0000000) != 0)
										attrib &= 0x7FFF;

									SetFileAttributes (dest_path->buffer, attrib);
								}
							}

							File_Close (&out_file);
						}
					}
				}

				_r_obj_dereference (dest_path);

				if (!result)
					result = TRUE;
			}

			if (root_dir_name)
				_r_obj_dereference (root_dir_name);

			ISzAlloc_Free (&alloc_imp, out_buffer);
		}
	}

	_r_mem_free (temp_buff);
	SzArEx_Free (&db, &alloc_imp);

	ISzAlloc_Free (&alloc_imp, look_stream.buf);

	File_Close (&archive_stream.file);

	return result;
}

BOOLEAN _app_unpack_zip (_In_ PVOID ctx, _In_ PBROWSER_INFORMATION pbi, _In_ PR_STRINGREF bin_name)
{
	mz_zip_archive zip_archive;
	mz_bool zip_bool;

	PR_BYTE bytes;
	PR_STRING root_dir_name = NULL;
	BOOLEAN result = FALSE;
	NTSTATUS status;

	status = _r_str_unicode2multibyte (&pbi->cache_path->sr, &bytes);

	if (status != STATUS_SUCCESS)
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"_r_str_unicode2multibyte", status, NULL);

		goto CleanupExit;
	}

	RtlZeroMemory (&zip_archive, sizeof (zip_archive));

	zip_bool = mz_zip_reader_init_file (&zip_archive, bytes->buffer, 0);

	if (!zip_bool)
	{
		//_r_log (LOG_LEVEL_ERROR, NULL, L"mz_zip_reader_init_file", GetLastError (), NULL);

		goto CleanupExit;
	}

	R_STRINGREF separator_sr = PR_STRINGREF_INIT (L"\\");
	R_BYTEREF path_sr;
	PR_STRING path;

	mz_zip_archive_file_stat file_stat;
	ULONG64 total_size = 0;
	ULONG64 total_read = 0; // this is our progress so far
	SIZE_T length;
	INT total_files;

	total_files = mz_zip_reader_get_num_files (&zip_archive);

	// find root directory which contains main executable
	for (INT i = 0; i < total_files; i++)
	{
		if (mz_zip_reader_is_file_a_directory (&zip_archive, i) || !mz_zip_reader_file_stat (&zip_archive, i, &file_stat))
			continue;

		if (file_stat.m_is_directory)
			continue;

		// count total size of unpacked files
		total_size += file_stat.m_uncomp_size;

		if (!root_dir_name)
		{
			_r_obj_initializebyteref (&path_sr, file_stat.m_filename);

			if (_r_str_multibyte2unicode (&path_sr, &path) != STATUS_SUCCESS)
				continue;

			_r_str_replacechar (&path->sr, L'/', OBJ_NAME_PATH_SEPARATOR);

			length = path->length - bin_name->length - separator_sr.length;

			if (_r_str_isendsswith (&path->sr, bin_name, TRUE) && path->buffer[length / sizeof (WCHAR)] == OBJ_NAME_PATH_SEPARATOR)
			{
				_r_obj_movereference (&root_dir_name, _r_obj_createstring_ex (path->buffer, path->length - bin_name->length));

				_r_str_trimstring (root_dir_name, &separator_sr, 0);
			}

			_r_obj_dereference (path);
		}
	}

	for (INT i = 0; i < total_files; i++)
	{
		if (!mz_zip_reader_file_stat (&zip_archive, i, &file_stat))
			continue;

		_r_obj_initializebyteref (&path_sr, file_stat.m_filename);

		if (_r_str_multibyte2unicode (&path_sr, &path) != STATUS_SUCCESS)
			continue;

		_r_str_replacechar (&path->sr, L'/', OBJ_NAME_PATH_SEPARATOR);
		_r_str_trimstring (path, &separator_sr, 0);

		// skip non-root dirs
		if (!_r_obj_isstringempty (root_dir_name) && (path->length <= root_dir_name->length || !_r_str_isstartswith (&path->sr, &root_dir_name->sr, TRUE)))
			continue;

		PR_STRING dest_path;

		if (root_dir_name)
			_r_obj_skipstringlength (&path->sr, root_dir_name->length + separator_sr.length);

		dest_path = _r_obj_concatstringrefs (3, &pbi->binary_dir->sr, &separator_sr, &path->sr);

		_app_extractupdate_callback (total_read, total_size, ctx);

		if (mz_zip_reader_is_file_a_directory (&zip_archive, i))
		{
			_r_fs_mkdir (dest_path->buffer);
		}
		else
		{
			PR_STRING sub_dir = _r_path_getbasedirectory (&dest_path->sr);

			if (sub_dir)
			{
				if (!_r_fs_exists (sub_dir->buffer))
					_r_fs_mkdir (sub_dir->buffer);

				_r_obj_dereference (sub_dir);
			}

			if (_r_str_unicode2multibyte (&dest_path->sr, &bytes) != STATUS_SUCCESS)
				continue;

			if (!mz_zip_reader_extract_to_file (&zip_archive, i, bytes->buffer, MZ_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY))
			{
				_r_log (LOG_LEVEL_ERROR, NULL, L"mz_zip_reader_extract_to_file", GetLastError (), dest_path->buffer);
				continue;
			}

			total_read += file_stat.m_uncomp_size;
		}

		_r_obj_dereference (dest_path);

		if (!result)
			result = TRUE;
	}

CleanupExit:

	if (bytes)
		_r_obj_dereference (bytes);

	if (root_dir_name)
		_r_obj_dereference (root_dir_name);

	mz_zip_reader_end (&zip_archive);

	return result;
}

INT _app_installupdate (_In_ PVOID ctx, _Inout_ PBROWSER_INFORMATION pbi)
{
	R_STRINGREF bin_name;
	INT errorcode = 0;

	_r_queuedlock_acquireshared (&lock_download);

	if (!_r_fs_exists (pbi->binary_dir->buffer))
		_r_fs_mkdir (pbi->binary_dir->buffer);

	_app_cleanupoldbinary (pbi);

	_r_path_getpathinfo (&pbi->binary_path->sr, NULL, &bin_name);

	_r_sys_setthreadexecutionstate (ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);

	if (!_app_unpack_zip (ctx, pbi, &bin_name) && !_app_unpack_7zip (ctx, pbi, &bin_name))
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"Cannot unpack archive", errorcode, pbi->cache_path->buffer);
		errorcode = (INT) GetLastError ();
		if (!errorcode) errorcode = ERROR_BAD_FORMAT;
	}


	if (!errorcode)
	{
		_r_obj_movereference (&pbi->current_version, _r_res_queryversionstring (pbi->binary_path->buffer));

		_app_cleanupoldmanifest (pbi);
	}
	else
	{
		_r_log (LOG_LEVEL_ERROR, NULL, TEXT (__FUNCTION__), errorcode, pbi->cache_path->buffer);

		_r_fs_deletedirectory (pbi->binary_dir->buffer, FALSE); // no recurse
	}

	_r_fs_deletefile (pbi->cache_path->buffer, TRUE); // remove cache file when zip cannot be opened


	_r_queuedlock_releaseshared (&lock_download);

	_r_sys_setthreadexecutionstate (ES_CONTINUOUS);


	return errorcode;
}

VOID _app_threadentry_check_for_new_version (_In_ PVOID arglist, _In_ ULONG busy_count)
{
	PTHREAD_CHECKVERSION_CONTEXT task = (PTHREAD_CHECKVERSION_CONTEXT)arglist;
	PR_STRING version_url = NULL;
	task->errorcode = _app_fetch_version_info_from_url (task->pbi, &version_url);
	if (task->errorcode)
		task->error_context = _r_format_string (L"Failed fetching version from\r\n%s", _r_obj_getstring (_r_config_getstring (L"ChromiumUpdateUrl", CHROMIUM_UPDATE_URL)));
	else if (version_url)
		_r_obj_dereference (version_url);
}

PTHREAD_UPDATER_RESULT _app_thread_result_alloc_init (_In_ INT task_idmsg, _In_opt_ PBROWSER_INFORMATION pbi, _In_ INT errorcode, _In_opt_ PR_STRING error_context)
{
	PTHREAD_UPDATER_RESULT evt = _r_mem_allocatezero (sizeof (THREAD_UPDATER_RESULT));
	memset (evt, 0, sizeof (THREAD_UPDATER_RESULT));
	evt->task_idmsg = task_idmsg;
	if (pbi) {
		evt->updated_bi = *pbi; // does not make copies of PR_STRINGs and does not move references!

		// This sucks, I will go back to C++
		evt->updated_bi.browser_name = _r_obj_safecopystring (pbi->browser_name);
		evt->updated_bi.browser_type = _r_obj_safecopystring (pbi->browser_type);
		evt->updated_bi.cache_path = _r_obj_safecopystring (pbi->cache_path);
		evt->updated_bi.binary_dir = _r_obj_safecopystring (pbi->binary_dir);
		evt->updated_bi.binary_path = _r_obj_safecopystring (pbi->binary_path);
		evt->updated_bi.download_url = _r_obj_safecopystring (pbi->download_url);
		evt->updated_bi.current_version = _r_obj_safecopystring (pbi->current_version);
		evt->updated_bi.new_version = _r_obj_safecopystring (pbi->new_version);
	}
	if (error_context)
	{
		evt->error_context = _r_obj_safecopystring (error_context);
		_r_obj_dereference (error_context);
	}
		

	return evt;
}

PTHREAD_UPDATER_CONTEXT _app_thread_ctxt_alloc_init (_In_ HWND hwnd, _In_ PCONSTCMDLINE_OPTS pcopts)
{
	PTHREAD_UPDATER_CONTEXT evt = _r_mem_allocatezero (sizeof (THREAD_UPDATER_CONTEXT));
	evt->hwnd = hwnd;
	evt->pcopts = pcopts;
	return evt;
}

typedef VOID (NTAPI *PCALLBACK_THREAD_STATUS_FUNC) (
	_In_ PVOID ctxt,
	_In_ INT task_idmsg,
	_In_opt_ PBROWSER_INFORMATION updated_pbi,
	_In_opt_ INT errorcode,
	_In_opt_ PR_STRING error_context
	);

INT _app_thread_updater_impl (_Inout_ PBROWSER_INFORMATION pbi, PCALLBACK_THREAD_STATUS_FUNC statusCb, PVOID ctx)
{
	INT errorcode;
	PR_STRING err_ctxt_msg = NULL;


	statusCb (ctx, IDM_TASK_FETCH_VERSION, NULL, 0, NULL);

	//BOOLEAN is_checkversion = _app_need_fetch_remote_version (pbi);

	PR_STRING version_url = NULL;

	errorcode = _app_fetch_version_info_from_url (pbi, &version_url);

	if (errorcode)
		err_ctxt_msg = _r_format_string (L"Failed fetching version from\r\n%s", _r_obj_getstring (version_url));
	else if (version_url)
		_r_obj_dereference (version_url);

	statusCb (ctx, IDM_TASK_FETCH_VERSION, pbi, errorcode, err_ctxt_msg);

	if (errorcode)
		return errorcode;


	BOOLEAN is_exists = _r_fs_exists (pbi->binary_path->buffer);
	BOOLEAN is_outdated = _app_is_local_version_outdated (pbi);

	if (is_exists && !is_outdated)
	{
		statusCb (ctx, IDM_TASK_UP_TO_DATE, pbi, 0, NULL);
		return 0;
	}


	statusCb (ctx, IDM_TASK_DOWNLOAD, NULL, 0, NULL);

	errorcode = _app_downloadupdate (ctx, pbi);


	if (errorcode)
		err_ctxt_msg = _r_format_string (L"Failed downloading update from\r\n%s", _r_obj_getstring (pbi->download_url));

	statusCb (ctx, IDM_TASK_DOWNLOAD, pbi, errorcode, err_ctxt_msg);

	if (errorcode)
		return errorcode;


	if (_app_browserisrunning (pbi))
	{
		err_ctxt_msg = _r_format_string (L"Browser is running. Cannot write to % s", pbi->binary_path->buffer);
		statusCb (ctx, IDM_TASK_BROWSER_RUNNING, pbi, 0, err_ctxt_msg);
		return 0;
	}

	statusCb (ctx, IDM_TASK_INSTALLATION, NULL, 0, NULL);

	errorcode = _app_installupdate (ctx, pbi);

	if (errorcode)
		err_ctxt_msg = _r_format_string (L"Failed installing browswer\r\nDownloaded file: %s\r\nInstall path: %s",
										 _r_obj_getstring (pbi->cache_path),
										 _r_obj_getstring (pbi->binary_dir));

	statusCb (ctx, IDM_TASK_INSTALLATION, pbi, errorcode, err_ctxt_msg);

	return errorcode;
}

VOID _app_thread_updater_status_cb (
	_In_ PVOID ctxt,
	_In_ INT task_idmsg,
	_In_opt_ PBROWSER_INFORMATION updated_pbi,
	_In_opt_ INT errorcode,
	_In_opt_ PR_STRING error_context
)
{

	PTHREAD_UPDATER_CONTEXT pupdatercontext = (PTHREAD_UPDATER_CONTEXT)ctxt;

	if (!updated_pbi && !errorcode)
	{
		switch (task_idmsg)
		{
			case IDM_TASK_DOWNLOAD:
				_r_progress_setmarquee (pupdatercontext->hwnd, IDC_PROGRESS, FALSE);
				_app_setstatus (pupdatercontext->hwnd, _r_locale_getstring (IDS_STATUS_DOWNLOAD), 0, 0);
				break;
			case IDM_TASK_INSTALLATION:
				_app_setstatus (pupdatercontext->hwnd, _r_locale_getstring (IDS_STATUS_INSTALL), 0, 0);
				break;
			default:
				break;
		}
	}

	if (errorcode && error_context)
	{
		_r_log (LOG_LEVEL_ERROR, &GUID_TrayIcon, L"UpdateTask", errorcode, _r_obj_getstring (error_context));
	}

	if (updated_pbi)
	{
		// copy new browser_info and send it to main thread
		SendMessage (pupdatercontext->hwnd, APP_WM_FROMTHREAD, (WPARAM)task_idmsg, (LPARAM)_app_thread_result_alloc_init (task_idmsg, updated_pbi, errorcode, error_context));
	}
}

VOID _app_threadentry_updater (_In_ PVOID arglist, _In_ ULONG busy_count)
{
	PTHREAD_UPDATER_CONTEXT pupdatercontext = (PTHREAD_UPDATER_CONTEXT)arglist;

	HWND hwnd = (HWND)pupdatercontext->hwnd;
	// Use thread local bi
	PBROWSER_INFORMATION pbi = _r_mem_allocatezero (sizeof (BROWSER_INFORMATION));

	init_browser_info (pbi, pupdatercontext->pcopts);


	INT errorcode = _app_thread_updater_impl (pbi, _app_thread_updater_status_cb, (PVOID) pupdatercontext);

	_r_mem_free (pbi);

}

VOID _app_initialize ()
{
	static R_INITONCE init_once = PR_INITONCE_INIT;

	if (_r_initonce_begin (&init_once))
	{
		_r_workqueue_initialize (&workqueue, 0, 1, 1000, NULL);

		_r_initonce_end (&init_once);
	}
}

VOID _app_destroy ()
{
	_r_workqueue_waitforfinish (&workqueue);
	_r_workqueue_destroy (&workqueue);
}

INT_PTR CALLBACK DlgProc (_In_ HWND hwnd, _In_ UINT msg, _In_ WPARAM wparam, _In_ LPARAM lparam)
{
	// will all be NULL until WM_INITDIALOG, must not be NULL after
	PAPPWINDOW_CONTEXT pappcontext = (PAPPWINDOW_CONTEXT) GetProp (hwnd, L"appcontext");
	PBROWSER_INFORMATION browser_info = pappcontext ? pappcontext->pbi : NULL;
	PBROWSER_PROCESS_ARGS browser_args = pappcontext ? pappcontext->pba : NULL;

	switch (msg)
	{
		case WM_INITDIALOG:
		{
			HWND htip;
			assert (lparam);
			if (!lparam)
			{
				_r_log_v (LOG_LEVEL_CRITICAL, &GUID_TrayIcon, L"WM_INITDIALOG", 0, L"unexpected lparam appcontext == NULL");
				PostQuitMessage (1);
				return 0;
			}
			pappcontext = (PAPPWINDOW_CONTEXT)lparam; // must not be NULL after
			SetProp (hwnd, L"appcontext", pappcontext);
			SetProp (hwnd, L"browser_started", 0);

			htip = _r_ctrl_createtip (hwnd);

			if (htip)
			{
				_r_ctrl_settiptext (htip, hwnd, IDC_BROWSER_DATA, LPSTR_TEXTCALLBACK);
				_r_ctrl_settiptext (htip, hwnd, IDC_CURRENTVERSION_DATA, LPSTR_TEXTCALLBACK);
				_r_ctrl_settiptext (htip, hwnd, IDC_VERSION_DATA, LPSTR_TEXTCALLBACK);
				_r_ctrl_settiptext (htip, hwnd, IDC_DATE_DATA, LPSTR_TEXTCALLBACK);
			}

			break;
		}

		case RM_INITIALIZE:
		{
			LONG dpi_value;

			LONG icon_small_x;
			LONG icon_small_y;

			HICON hicon;

			dpi_value = _r_dc_gettaskbardpi ();

			icon_small_x = _r_dc_getsystemmetrics (SM_CXSMICON, dpi_value);
			icon_small_y = _r_dc_getsystemmetrics (SM_CYSMICON, dpi_value);

			hicon = _r_sys_loadsharedicon (_r_sys_getimagebase (), MAKEINTRESOURCE (IDI_MAIN), icon_small_y, icon_small_x);

			_r_tray_create (hwnd, &GUID_TrayIcon, RM_TRAYICON, hicon, _r_app_getname (), FALSE);

			break;
		}

		case RM_UNINITIALIZE:
		{
			_r_tray_destroy (hwnd, &GUID_TrayIcon);
			break;
		}

		case RM_LOCALIZE:
		{

			// localize menu
			HMENU hmenu;

			hmenu = GetMenu (hwnd);

			if (hmenu)
			{
				_r_menu_setitemtext (hmenu, 0, TRUE, _r_locale_getstring (IDS_FILE));
				_r_menu_setitemtext (hmenu, 1, TRUE, _r_locale_getstring (IDS_SETTINGS));
				_r_menu_setitemtextformat (GetSubMenu (hmenu, 1), LANG_MENU, TRUE, L"%s (Language)", _r_locale_getstring (IDS_LANGUAGE));
				_r_menu_setitemtext (hmenu, 2, TRUE, _r_locale_getstring (IDS_HELP));

				_r_menu_setitemtextformat (hmenu, IDM_RUN, FALSE, L"%s...", _r_locale_getstring (IDS_RUN));
				_r_menu_setitemtextformat (hmenu, IDM_OPEN, FALSE, L"%s...", _r_locale_getstring (IDS_OPEN));
				_r_menu_setitemtext (hmenu, IDM_EXIT, FALSE, _r_locale_getstring (IDS_EXIT));
				_r_menu_setitemtext (hmenu, IDM_WEBSITE, FALSE, _r_locale_getstring (IDS_WEBSITE));
				_r_menu_setitemtextformat (hmenu, IDM_ABOUT, FALSE, L"%s\tF1", _r_locale_getstring (IDS_ABOUT));

				_r_locale_enum ((HWND)GetSubMenu (hmenu, 1), LANG_MENU, IDX_LANGUAGE); // enum localizations
			}
			_r_ctrl_setstring (hwnd, IDC_LINKS, L"<a href=\"" GIT_URL_NIDEFAWL_URL APP_NAME_SHORT "\">" GIT_URL_NIDEFAWL_SHORT APP_NAME_SHORT "</a>\r\n<a href=\"https://chromium.woolyss.com\">chromium.woolyss.com</a>");

			break;
		}

		case RM_INITIALIZE_POST:
		{
			assert (browser_info);

			update_browser_info (hwnd, browser_info);

			INT action = _app_getactionid (browser_info);
			_r_ctrl_setstring (hwnd, IDC_START_BTN, _r_locale_getstring (action));


			LPCWSTR status_string = L"";
			LPCWSTR status_data = L"";

			if (action != IDS_ACTION_CHECK)
			{
				status_string = _r_locale_getstring (action == IDS_ACTION_INSTALL ? IDS_STATUS_INSTALL : IDS_STATUS_DOWNLOAD);
				if (!_r_obj_isstringempty (browser_info->new_version))
					status_data = _r_obj_getstring (browser_info->new_version);
			}

			if (browser_info->is_onlyupdate || browser_info->is_bringtofront || !browser_info->is_autodownload)
			{
				_r_wnd_toggle (hwnd, TRUE);
			}
			else if (action != IDS_ACTION_CHECK)
			{
				_r_tray_popupformat (hwnd, &GUID_TrayIcon, NIIF_INFO, _r_app_getname (), status_string, status_data);
			}


			if (browser_info->is_autodownload)
			{
				_r_ctrl_enable (hwnd, IDC_START_BTN, FALSE);
				_r_workqueue_waitforfinish (&workqueue);
				_app_setstatus (hwnd, _r_locale_getstring (IDS_STATUS_CHECK), 0, 0);
				_r_progress_setmarquee (hwnd, IDC_PROGRESS, TRUE);
				_r_workqueue_queueitem (&workqueue, &_app_threadentry_updater, _app_thread_ctxt_alloc_init(hwnd, pappcontext->pcopts));
			}
			else
			{
				_r_ctrl_enable (hwnd, IDC_START_BTN, TRUE);

			}

			if (!browser_info->is_waitdownloadend && !_r_obj_isstringempty (browser_info->current_version) && !_app_isupdatedownloaded(browser_info))
			{
				_app_startbrowser_safe (browser_info, browser_args, hwnd);
			}

			break;
		}

		case RM_TASKBARCREATED:
		{
			assert (browser_info);

			LONG dpi_value;

			LONG icon_small_x;
			LONG icon_small_y;

			HICON hicon;

			dpi_value = _r_dc_gettaskbardpi ();

			icon_small_x = _r_dc_getsystemmetrics (SM_CXSMICON, dpi_value);
			icon_small_y = _r_dc_getsystemmetrics (SM_CYSMICON, dpi_value);

			hicon = _r_sys_loadsharedicon (_r_sys_getimagebase (), MAKEINTRESOURCE (IDI_MAIN), icon_small_x, icon_small_y);

			_r_tray_create (hwnd, &GUID_TrayIcon, RM_TRAYICON, hicon, _r_app_getname (), (_r_queuedlock_islocked (&lock_download) || _app_isupdatedownloaded (browser_info)) ? FALSE : TRUE);

			break;
		}

		case WM_DPICHANGED:
		{
			LONG dpi_value;

			LONG icon_small_x;
			LONG icon_small_y;

			HICON hicon;

			dpi_value = _r_dc_gettaskbardpi ();

			icon_small_x = _r_dc_getsystemmetrics (SM_CXSMICON, dpi_value);
			icon_small_y = _r_dc_getsystemmetrics (SM_CYSMICON, dpi_value);

			hicon = _r_sys_loadsharedicon (_r_sys_getimagebase (), MAKEINTRESOURCE (IDI_MAIN), icon_small_x, icon_small_y);

			_r_tray_setinfo (hwnd, &GUID_TrayIcon, hicon, _r_app_getname ());

			SendDlgItemMessage (hwnd, IDC_STATUSBAR, WM_SIZE, 0, 0);

			break;
		}

		case WM_CLOSE:
		{
			if (_r_queuedlock_islocked (&lock_download))
			{
				if (_r_show_message (hwnd, MB_YESNO | MB_ICONQUESTION, NULL, NULL, _r_locale_getstring (IDS_QUESTION_STOP)) != IDYES)
				{
					SetWindowLongPtr (hwnd, DWLP_MSGRESULT, TRUE);
					return TRUE;
				}
				PostQuitMessage (1);
			}

			DestroyWindow (hwnd);

			break;
		}

		case WM_DESTROY:
		{
			_r_tray_destroy (hwnd, &GUID_TrayIcon);

			SetProp (hwnd, L"pappcontext", NULL);

			PostQuitMessage (0);
			break;
		}

		case WM_LBUTTONDOWN:
		{
			PostMessage (hwnd, WM_SYSCOMMAND, SC_MOVE | HTCAPTION, 0);
			break;
		}

		case WM_ENTERSIZEMOVE:
		case WM_EXITSIZEMOVE:
		case WM_CAPTURECHANGED:
		{
			LONG_PTR exstyle;

			exstyle = _r_wnd_getstyle_ex (hwnd);

			if ((exstyle & WS_EX_LAYERED) == 0)
				_r_wnd_setstyle_ex (hwnd, exstyle | WS_EX_LAYERED);

			SetLayeredWindowAttributes (hwnd, 0, (msg == WM_ENTERSIZEMOVE) ? 100 : 255, LWA_ALPHA);
			SetCursor (LoadCursor (NULL, (msg == WM_ENTERSIZEMOVE) ? IDC_SIZEALL : IDC_ARROW));

			break;
		}
		case WM_CTLCOLORSTATIC:
			if (browser_info && _app_is_local_version_outdated (browser_info) && GetDlgCtrlID ((HWND)lparam) == IDC_VERSION_DATA)
			{
				HBRUSH hbr = (HBRUSH)DefWindowProc (hwnd, msg, wparam, lparam);
				SetTextColor ((HDC)wparam, RGB (55, 210, 55));
				return (INT_PTR)hbr;
			}
			if (browser_info && _app_is_local_version_outdated (browser_info) && GetDlgCtrlID ((HWND)lparam) == IDC_CURRENTVERSION_DATA)
			{
				HBRUSH hbr = (HBRUSH)DefWindowProc (hwnd, msg, wparam, lparam);
				SetTextColor ((HDC)wparam, RGB (210, 122, 55));
				return (INT_PTR)hbr;
			}
			return FALSE;
		case WM_DRAWITEM:
		{
			LPDRAWITEMSTRUCT draw_info;
			HDC buffer_hdc;
			HBITMAP buffer_bitmap;
			HGDIOBJ old_buffer_bitmap;

			draw_info = (LPDRAWITEMSTRUCT)lparam;

			if (draw_info->CtlID != IDC_LINE)
				break;

			buffer_hdc = CreateCompatibleDC (draw_info->hDC);

			if (buffer_hdc)
			{
				buffer_bitmap = CreateCompatibleBitmap (draw_info->hDC, _r_calc_rectwidth (&draw_info->rcItem), _r_calc_rectheight (&draw_info->rcItem));

				if (buffer_bitmap)
				{
					old_buffer_bitmap = SelectObject (buffer_hdc, buffer_bitmap);
					SetBkMode (buffer_hdc, TRANSPARENT);

					_r_dc_fillrect (buffer_hdc, &draw_info->rcItem, GetSysColor (COLOR_WINDOW));

					for (INT i = draw_info->rcItem.left; i < _r_calc_rectwidth (&draw_info->rcItem); i++)
						SetPixelV (buffer_hdc, i, draw_info->rcItem.top, GetSysColor (COLOR_APPWORKSPACE));

					BitBlt (draw_info->hDC, draw_info->rcItem.left, draw_info->rcItem.top, draw_info->rcItem.right, draw_info->rcItem.bottom, buffer_hdc, 0, 0, SRCCOPY);

					SelectObject (buffer_hdc, old_buffer_bitmap);

					SAFE_DELETE_OBJECT (buffer_bitmap);
				}

				SAFE_DELETE_DC (buffer_hdc);
			}

			SetWindowLongPtr (hwnd, DWLP_MSGRESULT, TRUE);
			return TRUE;
		}

		case WM_NOTIFY:
		{
			LPNMHDR lpnmhdr;

			lpnmhdr = (LPNMHDR)lparam;

			switch (lpnmhdr->code)
			{
				case TTN_GETDISPINFO:
				{
					WCHAR buffer[1024];
					PR_STRING string;
					INT ctrl_id;

					LPNMTTDISPINFO lpnmdi = (LPNMTTDISPINFO)lparam;

					if ((lpnmdi->uFlags & TTF_IDISHWND) == 0)
						break;

					ctrl_id = GetDlgCtrlID ((HWND)lpnmdi->hdr.idFrom);
					string = _r_ctrl_getstring (hwnd, ctrl_id);

					if (string)
					{
						_r_str_copy (buffer, RTL_NUMBER_OF (buffer), string->buffer);

						if (!_r_str_isempty (buffer))
							lpnmdi->lpszText = buffer;

						_r_obj_dereference (string);
					}

					break;
				}

				case NM_CLICK:
				case NM_RETURN:
				{
					PNMLINK nmlink;

					nmlink = (PNMLINK)lparam;

					if (!_r_str_isempty (nmlink->item.szUrl))
						_r_shell_opendefault (nmlink->item.szUrl);

					break;
				}
			}

			break;
		}

		case RM_TRAYICON:
		{
			switch (LOWORD (lparam))
			{
				case NIN_BALLOONUSERCLICK:
				{
					_r_wnd_toggle (hwnd, TRUE);
					break;
				}

				case NIN_KEYSELECT:
				{
					if (GetForegroundWindow () != hwnd)
					{
						_r_wnd_toggle (hwnd, FALSE);
					}

					break;
				}

				case WM_MBUTTONUP:
				{
					PostMessage (hwnd, WM_COMMAND, MAKEWPARAM (IDM_EXPLORE, 0), 0);
					break;
				}

				case WM_LBUTTONUP:
				{
					_r_wnd_toggle (hwnd, FALSE);
					break;
				}

				case WM_CONTEXTMENU:
				{
					assert (browser_info);

					HMENU hmenu;
					HMENU hsubmenu;

					SetForegroundWindow (hwnd); // don't touch

					hmenu = LoadMenu (NULL, MAKEINTRESOURCE (IDM_TRAY));

					if (hmenu)
					{
						hsubmenu = GetSubMenu (hmenu, 0);

						if (hsubmenu)
						{
							// localize
							_r_menu_setitemtext (hsubmenu, IDM_TRAY_SHOW, FALSE, _r_locale_getstring (IDS_TRAY_SHOW));
							_r_menu_setitemtextformat (hsubmenu, IDM_TRAY_RUN, FALSE, L"%s...", _r_locale_getstring (IDS_RUN));
							_r_menu_setitemtextformat (hsubmenu, IDM_TRAY_OPEN, FALSE, L"%s...", _r_locale_getstring (IDS_OPEN));
							_r_menu_setitemtext (hsubmenu, IDM_TRAY_WEBSITE, FALSE, _r_locale_getstring (IDS_WEBSITE));
							_r_menu_setitemtext (hsubmenu, IDM_TRAY_ABOUT, FALSE, _r_locale_getstring (IDS_ABOUT));
							_r_menu_setitemtext (hsubmenu, IDM_TRAY_EXIT, FALSE, _r_locale_getstring (IDS_EXIT));

							if (_r_obj_isstringempty (browser_info->binary_path) || !_r_fs_exists (browser_info->binary_path->buffer))
								_r_menu_enableitem (hsubmenu, IDM_TRAY_RUN, MF_BYCOMMAND, FALSE);

							_r_menu_popup (hsubmenu, hwnd, NULL, TRUE);
						}

						DestroyMenu (hmenu);
					}

					break;
				}
			}

			break;
		}

		// messages sent from worked thread
		case APP_WM_FROMTHREAD:
			assert (browser_info && lparam);

			PTHREAD_UPDATER_RESULT result = (PTHREAD_UPDATER_RESULT)lparam;

			INT task_idmsg = (INT)result->task_idmsg;

			if (result->errorcode)
			{
				_r_progress_setmarquee (hwnd, IDC_PROGRESS, FALSE);

				_r_tray_toggle (hwnd, &GUID_TrayIcon, TRUE);
				_r_wnd_toggle (hwnd, TRUE);
				_r_tray_popup (hwnd, &GUID_TrayIcon, NIIF_ERROR, _r_app_getname (), _r_locale_getstring (IDS_STATUS_ERROR)); // just inform user
				_app_setstatus (hwnd, _r_locale_getstring (IDS_STATUS_ERROR), 0, 0);


				_r_show_errormessage_ex (hwnd, _r_locale_getstring (IDS_STATUS_ERROR_UPDATE_FAILED), result->errorcode, NULL, result->error_context);
				_r_log (LOG_LEVEL_ERROR, &GUID_TrayIcon, L"UpdateTask", result->errorcode, _r_obj_getstring (result->error_context));

				_r_ctrl_enable (hwnd, IDC_START_BTN, TRUE);
				_r_ctrl_setstring (hwnd, IDC_START_BTN, _r_locale_getstring (_app_getactionid (browser_info)));

			}
			else
			{
				*browser_info = result->updated_bi;
				update_browser_info (hwnd, browser_info);
				switch (task_idmsg)
				{
					case IDM_TASK_BROWSER_RUNNING:
						_r_progress_setmarquee (hwnd, IDC_PROGRESS, FALSE);
						_r_ctrl_enable (hwnd, IDC_START_BTN, TRUE);
						_r_ctrl_setstring (hwnd, IDC_START_BTN, _r_locale_getstring (_app_getactionid (browser_info)));
						_r_status_settext (hwnd, IDC_STATUSBAR, 0, _r_obj_getstring (result->error_context));
						_r_tray_toggle (hwnd, &GUID_TrayIcon, TRUE);
						_r_tray_popup (hwnd, &GUID_TrayIcon, NIIF_INFO, _r_app_getname (), _r_obj_getstring (result->error_context)); // just inform user
						break;
					case IDM_TASK_UP_TO_DATE:
					{

						PR_STRING date_dormat = _r_format_unixtime_ex (_r_unixtime_now (), FDTF_SHORTDATE | FDTF_LONGTIME);
						if (date_dormat)
						{
							_r_status_settextformat (hwnd, IDC_STATUSBAR, 0, L"%s %s", date_dormat->buffer, L"Up to date");
							_r_obj_dereference (date_dormat);
						}
						// no-break

					}
					case IDM_TASK_INSTALLATION:
					{
						LONG64 tm_now = _r_unixtime_now ();
						_r_config_setlong64 (L"ChromiumLastCheck", tm_now);

						_r_progress_setmarquee (hwnd, IDC_PROGRESS, FALSE);
						_r_ctrl_enable (hwnd, IDC_START_BTN, TRUE);
						_r_ctrl_setstring (hwnd, IDC_START_BTN, _r_locale_getstring (_app_getactionid (browser_info)));
						if (task_idmsg == IDM_TASK_INSTALLATION)
							_r_status_settext (hwnd, IDC_STATUSBAR, 0, L"Installation complete");

						if (!browser_info->is_onlyupdate)
						{
							if (!GetProp (hwnd, L"browser_started"))
							{
								_app_startbrowser_safe (browser_info, browser_args, hwnd);
							}

							PostMessage (hwnd, WM_CLOSE, 0, 0);
						}
						break;
					}
				}
			}
			if (result->error_context)
				_r_obj_dereference (result->error_context);
			// leaking all the other strings here... I can't be bothered
			_r_mem_free (result);
			break;

		case WM_COMMAND:
		{
			assert (browser_info);
			if (!browser_info)
				return 0;

			if (HIWORD (wparam) == 0 && LOWORD (wparam) >= IDX_LANGUAGE && LOWORD (wparam) <= IDX_LANGUAGE + _r_locale_getcount ())
			{
				_r_locale_apply (GetSubMenu (GetSubMenu (GetMenu (hwnd), 1), LANG_MENU), LOWORD (wparam), IDX_LANGUAGE);
				return FALSE;
			}

			switch (LOWORD (wparam))
			{
				case IDCANCEL: // process Esc key
				case IDM_TRAY_SHOW:
				{
					_r_wnd_toggle (hwnd, FALSE);
					break;
				}

				case IDM_EXIT:
				case IDM_TRAY_EXIT:
				{
					PostMessage (hwnd, WM_CLOSE, 0, 0);
					break;
				}

				case IDM_RUN:
				case IDM_TRAY_RUN:
				{
					_app_startbrowser_safe (browser_info, browser_args, hwnd);
					break;
				}

				case IDM_OPEN:
				case IDM_TRAY_OPEN:
				{
					PR_STRING path;

					path = _r_app_getconfigpath ();

					if (_r_fs_exists (path->buffer))
						_r_shell_opendefault (path->buffer);

					break;
				}

				case IDM_EXPLORE:
				{
					if (browser_info->binary_dir)
					{
						if (_r_fs_exists (browser_info->binary_dir->buffer))
							_r_shell_opendefault (browser_info->binary_dir->buffer);
					}

					break;
				}

				case IDM_WEBSITE:
				case IDM_TRAY_WEBSITE:
				{
					_r_shell_opendefault (_r_app_getwebsite_url ());
					break;
				}

				case IDM_ABOUT:
				case IDM_TRAY_ABOUT:
				{
					_r_show_aboutmessage (hwnd);
					break;
				}

				case IDC_START_BTN:
				{

					if (!_r_queuedlock_islocked (&lock_download))
					{
						_r_ctrl_enable (hwnd, IDC_START_BTN, FALSE);
						_r_workqueue_waitforfinish (&workqueue);
						_app_setstatus (hwnd, _r_locale_getstring (IDS_STATUS_CHECK), 0, 0);
						_r_progress_setmarquee (hwnd, IDC_PROGRESS, TRUE);
						_r_workqueue_queueitem (&workqueue, &_app_threadentry_updater, _app_thread_ctxt_alloc_init (hwnd, pappcontext->pcopts));
					}
					break;
				}
			}

			break;
		}
	}

	return 0;
}

BOOLEAN isNetworkError (INT errorcode)
{
	return errorcode == ERROR_WINHTTP_TIMEOUT || errorcode == ERROR_WINHTTP_NAME_NOT_RESOLVED || errorcode == ERROR_WINHTTP_CANNOT_CONNECT;
}
INT run_application (_In_ PCONSTCMDLINE_OPTS pcopts)
{
	BROWSER_INFORMATION app_browser_info = {0};
	BROWSER_PROCESS_ARGS app_browser_args = {0};
	PBROWSER_INFORMATION browser_info = &app_browser_info;
	PBROWSER_PROCESS_ARGS browser_args = &app_browser_args;
	THREAD_CHECKVERSION_CONTEXT checkversion_context = {0};
	BOOLEAN is_exists;
	BOOLEAN is_checkversion;
	BOOLEAN is_outdated;

	// load configuration and apply command line switches
	init_browser_info (browser_info, pcopts);

	// load process args from config and apply command line args
	init_browser_args (browser_args, pcopts);


	checkversion_context.pbi = browser_info;
	checkversion_context.errorcode = 0;

	is_exists = _r_fs_exists (browser_info->binary_path->buffer);
	is_checkversion = _app_need_fetch_remote_version (browser_info);
	is_outdated = _app_is_local_version_outdated (browser_info);

	_r_log_v (LOG_LEVEL_DEBUG, &GUID_TrayIcon, L"before_window", 0, L"binary_path %s", _r_obj_getstring (browser_info->binary_path));
	_r_log_v (LOG_LEVEL_DEBUG, &GUID_TrayIcon, L"before_window", 0, L"Local version %s", _r_obj_getstring (browser_info->current_version));

	if (!is_exists || is_checkversion)
	{
		checkversion_context.errorcode = -1;

		// start a task on a thread to check for a new version
		// this could be done on the current thread, since we have a blocking wait after
		_r_workqueue_queueitem (&workqueue, &_app_threadentry_check_for_new_version, &checkversion_context);

		// wait for thread task to finish (blocking)
		_r_workqueue_waitforfinish (&workqueue);

		_r_log_v (LOG_LEVEL_DEBUG, &GUID_TrayIcon, L"before_window", checkversion_context.errorcode, L"TASK_CHECK_VERSION errorcode %d", checkversion_context.errorcode);
		_r_log_v (LOG_LEVEL_DEBUG, &GUID_TrayIcon, L"before_window", 0, L"Remote version %s", _r_obj_getstring (browser_info->new_version));

		if (!checkversion_context.errorcode)
		{
			is_outdated = _app_is_local_version_outdated (browser_info);

			if (is_exists && !is_outdated)
			{
				LONG64 tm_now = _r_unixtime_now ();
				_r_config_setlong64 (L"ChromiumLastCheck", tm_now);
			}
		}
		else if (_r_config_getboolean(L"IgnoreStartupNetworkErrors", false)
				 && isNetworkError(checkversion_context.errorcode)
				 && is_exists
				 && !_r_obj_isstringempty (browser_info->current_version))
		{
			checkversion_context.errorcode = 0;
		}
	}

	if (is_checkversion)
		_r_log_v (LOG_LEVEL_DEBUG, &GUID_TrayIcon, L"before_window", 0, L"is_outdated: %d", is_outdated);


	// Open browser if we are up to date
	if (is_exists && !browser_info->is_onlyupdate && !is_outdated)
	{

		PR_STRING browser_cmdline_inspect = {0};
		INT errorcode = _app_startbrowser (browser_info, browser_args, &browser_cmdline_inspect);

		if (!errorcode && checkversion_context.errorcode == 0)
			return 0; // Exit only if browser was started successfully

		if (errorcode)
		{
			_r_show_errormessage_ex (NULL, _r_locale_getstring (IDS_STATUS_ERROR_RUN_PROCESS), errorcode, NULL, browser_cmdline_inspect);
		}

		if (browser_cmdline_inspect)
			_r_obj_dereference (browser_cmdline_inspect);


		// Opening browser failed or version failed
	}

	APPWINDOW_CONTEXT appcontext = {pcopts, browser_info, browser_args, NULL, 0};

	appcontext.hwnd = _r_app_createwindow_ex (NULL, MAKEINTRESOURCE (IDD_MAIN), MAKEINTRESOURCE (IDI_MAIN), NULL, &DlgProc, &appcontext);

	if (!appcontext.hwnd)
		return (INT) GetLastError (); // window creation failed

	// pass along message loop return value as exit code
	return _r_wnd_messageloop (appcontext.hwnd, MAKEINTRESOURCE (IDA_MAIN));
}


VOID parse_commandline (_In_ LPWSTR cmdline, _Inout_ PCMDLINE_OPTS popts)
{
	LPWSTR *arga;
	INT numargs;

	if (popts)
		memset (popts, 0, sizeof (PCMDLINE_OPTS));

	arga = CommandLineToArgvW (cmdline, &numargs);

	if (arga && popts)
	{
		LPWSTR key;
		PR_STRING pass_args = NULL;

		for (INT i = 1; i < numargs; i++)
		{
			key = arga[i];

			if (_r_str_compare_length (key, L"/autodownload", 13) == 0)
			{
				popts->is_autodownload = TRUE;
			}
			else if (_r_str_compare_length (key, L"/bringtofront", 13) == 0)
			{
				popts->is_bringtofront = TRUE;
			}
			else if (_r_str_compare_length (key, L"/forcecheck", 11) == 0)
			{
				popts->is_forcecheck = TRUE;
			}
			else if (_r_str_compare_length (key, L"/wait", 5) == 0)
			{
				popts->is_waitdownloadend = TRUE;
			}
			else if (_r_str_compare_length (key, L"/update", 7) == 0)
			{
				popts->is_onlyupdate = TRUE;
			}
			else if (_r_str_compare_length (key, L"/ini", 4) == 0)
			{
				if (i + 1 < numargs)
				{
					_r_log (LOG_LEVEL_DEBUG, NULL, L"ini_path", i + 1, arga[i + 1]);
					popts->ini_path = _r_obj_createstring (arga[i + 1]);
					i++;
				}
			}
			else
			{
				_r_log (LOG_LEVEL_DEBUG, NULL, L"Browser arg", i, key);
				// append all unused arguments to string pass_args
				// add a space if it is not the first argument
				_r_obj_movereference (&pass_args, _r_obj_concatstrings (3, _r_obj_getstring (pass_args), pass_args ? L" " : NULL, arga[i]));
			}

		}

		LocalFree (arga);

		if (pass_args)
			_r_obj_movereference (&popts->optional_argv, pass_args);
	}
}


CMDLINE_OPTS cmdline_opts;

BOOLEAN _r_sys_getopt (
	_In_ LPCWSTR args,
	_In_ LPCWSTR name,
	_Out_opt_ PR_STRING_PTR out_value
)
{
	if (out_value && !_r_str_compare (name, L"ini") && !_r_obj_isstringempty(cmdline_opts.ini_path))
	{
		*out_value = _r_obj_createstring2 (cmdline_opts.ini_path);
		return TRUE;
	}

	return FALSE;
}

INT APIENTRY wWinMain (_In_ HINSTANCE hinst, _In_opt_ HINSTANCE prev_hinst, _In_ LPWSTR cmdline, _In_ INT show_cmd)
{
	PR_STRING path;
	INT exitcode;

	if (!_r_app_initialize ())
		return ERROR_APP_INIT_FAILURE;

	// Parse command line
	parse_commandline (GetCommandLineW (), &cmdline_opts);

	_app_initialize ();

	path = _r_app_getdirectory ();

	SetCurrentDirectory (path->buffer);

	exitcode = run_application (&cmdline_opts);

	_app_destroy ();

	return exitcode;
}
