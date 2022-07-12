# OpenVAS Vulnerability Test
# $Id: popserver_detect.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: POP3 Server type and version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Updated by Paul Johnston for Westpoint Ltd <paul@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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

tag_summary = "The remote POP3 servers leak information about the software it is running, 
through the login banner. This may assist an attacker in choosing an attack 
strategy. 
 
Versions and types should be omitted where possible.";

tag_solution = "Change the login banner to something generic.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300005");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 name = "POP3 Server type and version";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl");
 script_require_ports("Services/pop3", 110);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

port = get_kb_item("Services/pop3");
if(!port) port = 110;
banner = get_service_banner_line(service:"pop3", port:port);

banner = ereg_replace(pattern:"\[.*\]", replace:"", string:banner);
banner = ereg_replace(pattern:"<.*>", replace:"", string:banner);
banner = ereg_replace(pattern:"POP3", replace:"", string:banner, icase:TRUE);

if(ereg(pattern:"[0-9]", string:banner))
{
  report = "
The remote POP3 servers leak information about the software it is running, 
through the login banner. This may assist an attacker in choosing an attack 
strategy. 
 
Versions and types should be omitted where possible.

The version of the remote POP3 server is : 
" + banner + "

Solution: Change the login banner to something generic.";
  log_message(port:port, data:report);
}
