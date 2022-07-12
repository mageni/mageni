# OpenVAS Vulnerability Test
# $Id: amanda_version.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Amanda Index Server version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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

tag_summary = "This test detects the Amanda Index Server's 
version by connecting to the server and processing the buffer received.
This information gives potential attackers additional information about the
system they are attacking. Version numbers should be omitted where possible.";

tag_solution = "Change the version number to something generic (like: 0.0.0.0)";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300003"); 
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

 name = "Amanda Index Server version";
 script_name(name);


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);
 script_require_ports("Services/amandaidx", 10082);
 script_dependencies("find_service.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


#
# The script code starts here
#
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.10742";
SCRIPT_DESC = "Amanda Index Server version";

register = 0;

port = get_kb_item("Services/amandaidx");
if (!port) {
  	register = 1;
  	port = 10082;
	}

if(!get_port_state(port))exit(0);

soctcp10082 = open_sock_tcp(port);
if (soctcp10082)
{
 result = recv_line(socket:soctcp10082, length:1000);
 
 Amanda_version = "";

 if ("AMANDA index server" >< result)
 {
  if (ereg(pattern:"^220 .* AMANDA index server \(.*\).*", string:result)) {
   Amanda_version = ereg_replace(pattern:"^220 .* AMANDA index server \((.*)\).*", string:result, replace:"\1");
   report = string("The remote Amanda Server version is : ",
  		Amanda_version, 
		"\n");
   set_kb_item(name:"Amanda/version", value:Amanda_version);
   if(register)register_service(port:port, proto:"amandaidx");

   ## build cpe and store it as host_detail
   cpe = build_cpe(value:Amanda_version, exp:"^([0-9.]+)", base:"cpe:/a:amanda:amanda:");
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  } else {
   report = string("Amanda Server is running with banner:\n",result);
  }
  log_message(port:port, data:report);
 }
 close(soctcp10082);
}
