###############################################################################
# OpenVAS Vulnerability Test
# $Id: open_X11_server.nasl 7422 2017-10-13 08:38:16Z cfischer $
#
# Open X Server
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15897");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-1999-0526");
  script_name("Open X Server");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2004 Michel Arboi");
  script_dependencies("X.nasl");
  script_require_ports("Services/X11", 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009);
  script_mandatory_keys("X11/open");

  script_tag(name:"summary", value:"An improperly configured X server will accept connections from clients from
  anywhere.");

  script_tag(name:"impact", value:"This allows an attacker to make a client connect to the X server to
  record the keystrokes of the user, which may contain sensitive information, such as account passwords.");

  script_tag(name:"solution", value:"Use xhost, MIT cookies, and filter incoming TCP connections to this port.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default:6000, proto:"X11");
open = get_kb_item( "X11/" + port + "/open" );
if( ! open )
  exit( 0 );

security_message( port:port, data:"This X server accepts clients from anywhere. This allows an attacker to connect to it and record any of your keystrokes." );
exit( 0 );