# OpenVAS Vulnerability Test
# $Id: putty_arbitrary_command_execution.nasl 11356 2018-09-12 10:46:43Z tpassfeld $
# Description: PuTTY window title escape character arbitrary command execution
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14262");
  script_version("$Revision: 11356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:46:43 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-0069");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PuTTY window title escape character arbitrary command execution");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_putty_portable_detect.nasl", "smb_reg_service_pack.nasl");
  script_require_keys("putty/version");
  script_tag(name:"solution", value:"Upgrade to version 0.54 or newer");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"PuTTY is a free SSH client.
  This version contains a flaw that may allow a malicious user to insert
  arbitrary commands and execute them.
  The issue is triggered when an attacker sends commands,
  preceded by terminal emulator escape sequences.
  It is possible that the flaw may allow arbitrary code execution
  resulting in a loss of integrity.");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

puttyVer=get_kb_item("putty/version");
if(!puttyVer){
  exit(0);
}

if(version_is_less_equal(version:puttyVer, test_version:"0.53")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

