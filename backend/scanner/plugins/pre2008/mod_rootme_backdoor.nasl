###############################################################################
# OpenVAS Vulnerability Test
# $Id: mod_rootme_backdoor.nasl 13685 2019-02-15 10:06:52Z cfischer $
#
# Apache mod_rootme Backdoor
#
# Authors:
# Noam Rathaus and upgraded by Alexei Chicheev for mod_rootme v.0.3 detection
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus and upgraded (15.03.2005) by Alexei Chicheev for mod_rootme v.0.3 detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.13644");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apache mod_rootme Backdoor");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Malware");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/banner");

  script_tag(name:"solution", value:"- Remove the mod_rootme module from httpd.conf/modules.conf

  - Consider reinstalling the computer, as it is likely to have been compromised by an intruder");

  script_tag(name:"summary", value:"The remote system appears to be running the mod_rootme module,
  this module silently allows a user to gain a root shell access to the machine via HTTP requests.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( ! banner || "Apache" >!< banner )
  exit(0);

if( http_get_is_marked_embedded( port:port ) )
  exit( 0 );

host = http_host_name(port:port);

soc = open_sock_tcp(port);
if (soc)
{
  # Syntax for this Trojan is essential... normal requests won't work...
  # We need to emulate a netcat, slow sending, single line each time, unlike HTTP that can
  # receive everything as a block
  send(socket:soc, data:string("GET root HTTP/1.0\n",
                               "Host: ", host,"\r\n"));
  sleep(1);
  send(socket:soc, data:string("\n"));
  sleep(1);
  res_vx = recv(socket:soc, length:1024);
  if ( ! res_vx )
    exit(0);

  send(socket:soc, data:string("id\r\n",
                               "Host: ", host, "\r\n"));
  res = recv(socket:soc, length:1024);
  if(!res)
    exit(0);

  if (ereg(pattern:"^uid=[0-9]+\(root\)", string:res) && ereg(pattern:"^rootme-[0-9].[0-9] ready", string:res_vx))
  {
    send(socket:soc, data:string("exit\r\n",
                                 "Host: ", host, "\r\n")); # If we don't exit we can cause Apache to crash
    security_message(port:port);
  }
  close(soc);
}
