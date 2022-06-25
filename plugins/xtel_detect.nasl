# OpenVAS Vulnerability Test
# $Id: xtel_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
# Description: xtel detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11121");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("xtel detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 1313);

  script_tag(name:"summary", value:"xteld is running on this port. This service allows users to
  connect to the 'Teletel' network. Some of the servers are expensive.
  Note that by default, xteld forbids access to the most expensive services.");

  exit(0);
}

include("host_details.inc");
include ("misc_func.inc");

function read_xteld(s)
{
  m = "";
  while (1)
  {
    r = recv(socket: s, length: 1);
    if (strlen(s) == 0) return (m);
    len = ord(r);
    if (len == 130) return (m);
    r1 = recv(socket: s, length: len);
    send(socket: s, data: raw_string(0x83));
    r = recv(socket: s, length: 1);
    if (strlen(s) == 0) return (m);
    len = ord(r);
    if (len == 130) return (m);
    r2 = recv(socket: s, length: len);
    send(socket: s, data: raw_string(0x82));
    m = string(m, r1, " - ", r2, "\n");
  }
}

vt_strings = get_vt_strings();
req1 = raw_string(6) + vt_strings["default"] + raw_string(0x82);

port = get_unknown_port( default:1313 );

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: req1);
m1 = read_xteld(s: soc);
close(soc);

if (m1)
{
  m2 = string(
"xteld tourne sur ce port. Ce service permet de se connecter sur le\n",
"réseau 'Télétel'. Certains des serveurs sont chers.\n",
"Voici les services autorisés ici :\n",
	m1,
"\nRisque : Aucun\n");
  log_message(port: port, data: m2);
  register_service(port: port, proto: "xtel");
}