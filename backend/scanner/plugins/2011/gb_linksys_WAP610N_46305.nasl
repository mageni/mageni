###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linksys_WAP610N_46305.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Linksys WAP610N Unauthenticated Root Access Security Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103080");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-18 16:40:55 +0100 (Fri, 18 Feb 2011)");
  script_bugtraq_id(46305);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Linksys WAP610N Unauthenticated Root Access Security Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46305");
  script_xref(name:"URL", value:"http://www.linksysbycisco.com/APAC/en/home");
  script_xref(name:"URL", value:"http://www.securenetwork.it/ricerca/advisory/download/SN-2010-08.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports(1111);
  script_tag(name:"summary", value:"The Linksys WAP610N is prone to a security vulnerability that allows
unauthenticated root access.

An attacker can exploit this issue to gain unauthorized root access to
affected devices. Successful exploits will result in the complete
compromise of an affected device.

Linksys WAP610N firmware versions 1.0.01 and 1.0.00 are vulnerable.
Other versions may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("telnet_func.inc");

port = 1111;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

telnet_negotiate(socket:soc);

send(socket:soc, data:string("system id\r\n"));
buf = recv(socket:soc, length:512);

close(soc);

if(egrep(pattern:"uid=0.*gid=0",string:buf)) {

  security_message(port:port);
  exit(0);
}

exit(0);
