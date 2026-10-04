
#include "Precomp.h"
#include "Utils/Exception.h"
#include "Utils/Logger.h"
#include "Utils/CommandLine.h"
#include "GameApp.h"
#include "GameFolder.h"
#include "Engine.h"
#include "UI/WidgetResourceData.h"
#include "UI/ErrorWindow/ErrorWindow.h"
#include "UI/Launcher/LauncherWindow.h"
#include "Utils/File.h"
#include <stdexcept>
#include <iostream>
#include "VM/Frame.h"
#include <csignal>
#include <cstdlib>
#include <unistd.h>

// SE_DEBUG_SEGV=1: on a crash, print the UnrealScript call stack (debugging aid, not async-signal-safe).
static void SegvHandler(int sig)
{
	std::string s = "\n[SEGV] signal " + std::to_string(sig) + " in script:\n" + Frame::GetCallstack() + "\n";
	(void)!write(2, s.data(), s.size());
	_exit(128 + sig);
}

int GameApp::main(Array<std::string> args)
{
	InitWidgetResources("dark");
	if (std::getenv("SE_DEBUG_SEGV"))
	{
		signal(SIGSEGV, SegvHandler);
		signal(SIGABRT, SegvHandler);
	}

	try
	{
		CommandLine cmd(args);
		commandline = &cmd;

		if (ErrorWindow::CheckCrashReporter())
			return 0;

		if (commandline->HasArg("-h", "--help"))
		{
			std::cout << "SurrealEngine [--url=<mapname>] [--engineversion=X] [--autostart] [Path to game folder]\n";
			return 0;
		}

		int selectedGameIndex = -1;
		if (commandline->HasArg("-a", "--autostart"))
		{
			// Skip the launcher and start the first game found (the folder given on the command line).
			GameFolderSelection::UpdateList();
			if (!GameFolderSelection::Games.empty())
				selectedGameIndex = 0;
		}
		else
		{
			selectedGameIndex = LauncherWindow::ExecModal();
		}
		if (selectedGameIndex >= 0)
		{
			GameLaunchInfo info = GameFolderSelection::GetLaunchInfo(selectedGameIndex);
			Engine engine(info);
			engine.Run();
		}
	}
	catch (const std::exception& e)
	{
		ErrorWindow::ExecModal(e.what(), Logger::Get()->GetLog());
	}

	DeinitWidgetResources();
	return 0;
}
