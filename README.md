chromiumlauncher
===============
### A small and very fast portable launcher and updater for Chromium

![chromiumlauncher-Release_2022-01-20_00-50-00](https://user-images.githubusercontent.com/637382/150237281-a4e6bf61-edf1-4bb8-9623-7d9ca8a0a68d.png)

### Settings

see default [chromiumlauncher.ini](https://github.com/nidefawl/chromiumlauncher/blob/3637da50a4057c233877035a18194eeaec8cf2da/bin/chromiumlauncher.ini)


### Command line:
All command line options start with a slash.  
Anything that doesn't match is passed thru to chrome.exe, no isUrl check is applied.  
All of these options (except /ini) can be set in the .ini file

~~~
/autodownload - auto download update and install it!
/bringtofront - bring chromiumlauncher window to front when download started
/forcecheck - force update checking
/wait - start browser only when check/download/install update complete
/update - use chromiumlauncher as updater, but does not start Chromium
/ini .\chromiumlauncher.ini - start chromiumlauncher with custom configuration
~~~

### If the SetDefaultBrowser.bat doesn't work for you:

Launch the browser then open [chrome://settings/defaultBrowser](chrome://settings/defaultBrowser) and click Make default.  
Then you have to can select the browser as your default one in windows.  
The final step is to adjust the shell path from bin/chrome.exe to chromiumlauncher.exe in the registry.  
You can find it in the key HKEY_CLASSES_ROOT/ChromiumHTM.XXXX/shell/open/command.  
For me the command was set to `"C:\Users\Michael\ChromiumPortable\bin\chrome.exe" --single-argument "%1"`  
I replaced `bin\chrome.exe` with `chromiumlauncher.exe`. This will make sure the launcher is triggered every time you start the browser or open a link.  

![regedit_2022-01-20_01-02-32](https://user-images.githubusercontent.com/637382/150238118-0516a908-8c98-492c-82db-b7eeb335a340.png)
