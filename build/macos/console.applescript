-- Operator console for EDR Agent. Compiled with osacompile into
-- /Applications/EDR Agent.app so Launchpad and Finder treat it as a real app.

on edrctlPath()
	set bundled to (POSIX path of (path to me)) & "Contents/MacOS/edrctl"
	try
		do shell script "/bin/test -x " & quoted form of bundled
		return bundled
	end try
	return "/usr/local/bin/edrctl"
end edrctlPath

on runEdrctl(args)
	set bin to edrctlPath()
	try
		return do shell script quoted form of bin & " " & args
	on error errMsg
		return errMsg
	end try
end runEdrctl

on runEdrctlAdmin(args)
	set bin to edrctlPath()
	try
		return do shell script quoted form of bin & " " & args with administrator privileges
	on error errMsg
		return errMsg
	end try
end runEdrctlAdmin

on clip(s)
	if length of s > 700 then
		return (text 1 thru 700 of s) & "…"
	end if
	return s
end clip

on run
	repeat
		set status to clip(runEdrctl("ui"))
		if status is "" then set status to "EDR Agent — choose an action"
		try
			set choice to choose from list {"Refresh status", "Enroll device", "Test connection", "Start agent", "Stop agent", "Quit"} with title "EDR Agent" with prompt status default items {"Refresh status"}
		on error
			display dialog "EDR Agent could not open the control window." buttons {"OK"} default button "OK" with title "EDR Agent"
			return
		end try
		if choice is false then return
		set item1 to item 1 of choice
		if item1 is "Quit" then return
		if item1 is "Refresh status" then
			-- loop
		else if item1 is "Enroll device" then
			try
				set r to display dialog "Paste the enrollment token from the XDR console." default answer "" with title "EDR Agent — Enroll" buttons {"Cancel", "Enroll"} default button "Enroll"
				if button returned of r is "Enroll" then
					set tok to text returned of r
					if tok is not "" then
						display dialog clip(runEdrctlAdmin("enroll --token " & quoted form of tok)) with title "Enroll" buttons {"OK"} default button "OK"
					end if
				end if
			end try
		else if item1 is "Test connection" then
			display dialog clip(runEdrctl("test-connection")) with title "Connection test" buttons {"OK"} default button "OK"
		else if item1 is "Start agent" then
			display dialog clip(runEdrctlAdmin("start")) with title "Start" buttons {"OK"} default button "OK"
		else if item1 is "Stop agent" then
			display dialog clip(runEdrctlAdmin("stop")) with title "Stop" buttons {"OK"} default button "OK"
		end if
	end repeat
end run
