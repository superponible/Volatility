# Volatility
#
# Authors:  Jared Atkinson 
# Contact:  <jared@invoke-ir.com> 
# Twitter:  @jaredcatkinson 
# Blog:     www.invoke-ir.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

import re
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.conf as conf
config = conf.ConfObject()

class malsysproc(common.AbstractWindowsCommand):
    """Find behaviors of a malicious lsass.exe or svchost.exe"""
   
    # Add functionality to look for child processes
#    def children_search(self, process, pid):
#	children = ''
#	
#	return children

    # Add functionality to deal with process injection

    # Test if network connections are occuring

    # Add functionality to deal with process owners

    def check_name(self, process, name):
    # Check for lookalike processes
	if name == "lsass":
	    return process.ImageFileName.lower() == "lsass.exe"
	elif name == "svchost":
	    return process.ImageFileName.lower() == "svchost.exe"

    def check_path(self, process, name):
    # Ensure process is running from correct Path
	if name == "lsass":
	    return str(process.Peb.ProcessParameters.ImagePathName).lower() == "c:\windows\system32\lsass.exe"
	elif name == "svchost":
	    return str(process.Peb.ProcessParameters.ImagePathName).lower() == "c:\windows\system32\svchost.exe"
	    
    def check_ppid(self, process, parentpid):
    # Ensure process was created by correct parent
	return process.InheritedFromUniqueProcessId == parentpid

    def check_time(self, process, ctime):
    # Ensure the process was created within 10 seconds of the parent process (have not performed complete testing for time)
	return process.CreateTime < ctime + 10

    def check_priority(self, process, name):
    # Ensure the process is running under the correct priority (applys only to lsass)
	if name == "lsass":
	    return process.Pcb.BasePriority == 9
	elif name == "svchost":
	    return "N/A"

    def check_cmdline(self, process, name):
    # Ensure the process is running with expected command line arguments
	if name == "lsass":
	    return str(process.Peb.ProcessParameters.CommandLine).lower() == "c:\windows\system32\lsass.exe"
	elif name == "svchost":
	    # Create an array of expected command line arguments for svchost.exe
	    cmdline_array = ["-k secsvcs",
                             "-k networkservice",
                             "-k dcomlaunch",
                             "-k rpcss",
                             "-k netsvcs",
                             "-k localservice",
                             "-k imgsvc",
                             "-ktermsvcs",
                             "-k regsvc",
                             "-k winerr",
                             "-k tapisrv",
                             "-k httpfilter",
                             "-k secvcs",
                             "-k gpsvcgroup",
                             "-k iissvcs",
                             "-k apphost",
                             "-k localsystemnetworkrestricted",
                             "-k wersvcgroup"
                             ]
	    if str(process.Peb.ProcessParameters.ImagePathName).lower() == "c:\windows\system32\svchost.exe":
		cmdline = False		
		for arg in cmdline_array:
		    if arg in str(process.Peb.ProcessParameters.CommandLine).lower():
			cmdline = True
			break
	    else:
		cmdline = False
	    return cmdline
	    

    def calculate(self):
	kernel_space = utils.load_as(self._config)
	lsasscounter = 0
        for process in tasks.pslist(kernel_space):
	    # In OS newer than XP lsass.exe's parent is wininit.exe
	    if "Win7" in config.PROFILE or "Vista" in config.PROFILE or "2008" in config.PROFILE:
	        if str(process.ImageFileName).lower() == "wininit.exe":
	            lsassparentpid = process.UniqueProcessId
	            lsassctime = process.CreateTime
	    # In OS XP and prior lsass.exe's parent is winlogon.exe
	    elif "2003" in config.PROFILE or "XP" in config.PROFILE:	        
		if str(process.ImageFileName).lower() == "winlogon.exe":
	            lsassparentpid = process.UniqueProcessId
	            lsassctime = process.CreateTime
	    if str(process.ImageFileName).lower() == "services.exe":
		svchostparentpid = process.UniqueProcessId
		svchostctime = process.CreateTime
	    # Look for processes that look similar to lsass.exe, but may have the "sas" characters switched around
 	    if re.match(r'l...s\.exe',str(process.ImageFileName).lower()) is not None:		
		# There should only be one lsass.exe
		lsasscounter += 1
		if lsasscounter > 1:
		    print("Multiple lsass.exe processes found. This is suspicious")		
		info = {}	        
		info['offset'] = process.obj_offset
	        info['processname'] = str(process.ImageFileName)
		info['pid'] = process.UniqueProcessId
	        info['name'] = self.check_name(process, "lsass")
	        info['path'] = self.check_path(process, "lsass")
	        info['ppid'] = self.check_ppid(process, lsassparentpid)
	        info['time'] = self.check_time(process, lsassctime)
	        info['priority'] = self.check_priority(process, "lsass")
	        info['cmdline'] = self.check_cmdline(process, "lsass")
		yield info
	    # Look for processes that look similar to svchost.exe, but may have the "vc" characters switched around
	    if re.match(r's..host\.exe',str(process.ImageFileName).lower()) is not None:
		info = {}	        
		info['offset'] = process.obj_offset
	        info['processname'] = str(process.ImageFileName)
		info['pid'] = process.UniqueProcessId
	        info['name'] = self.check_name(process, "svchost")
	        info['path'] = self.check_path(process, "svchost")
	        info['ppid'] = self.check_ppid(process, svchostparentpid)
	        info['time'] = self.check_time(process, svchostctime)
	        info['priority'] = self.check_priority(process, "svchost")
	        info['cmdline'] = self.check_cmdline(process, "svchost")
	        yield info		

    def render_text(self, outfd, data):
	print
	self.table_header(outfd, [("Offset", "[addrpad]"),
                                  ("ProcessName", "11"),
                                  ("PID", "5"),
                                  ("Name", "5"),
                                  ("Path", "5"),
                                  ("PPId", "5"),
                                  ("Time", "5"),
                                  ("Priority", "9"),
                                  ("Cmdline","7")
                                  ])  
	for info in data:
	    self.table_row(outfd,
                           info['offset'],
			   info['processname'],
                           info['pid'],
			   str(info['name']),
			   str(info['path']),
		 	   str(info['ppid']),
			   str(info['time']),
			   str(info['priority']),
			   str(info['cmdline'])
                           )
	print
