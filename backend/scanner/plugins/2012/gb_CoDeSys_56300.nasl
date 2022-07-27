###############################################################################
# OpenVAS Vulnerability Test
#
# CODESYS Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103599");
  script_cve_id("CVE-2012-6069", "CVE-2012-6068");
  script_bugtraq_id(56300);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2019-05-13T14:05:09+0000");

  script_name("CoDeSys Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56300");
  script_xref(name:"URL", value:"http://www.digitalbond.com/2012/10/25/new-project-basecamp-tools-for-codesys-200-vendors-affected/");
  script_xref(name:"URL", value:"http://www.3s-software.com/");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-13-011-01");

  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2012-10-29 18:46:26 +0100 (Mon, 29 Oct 2012)");
  script_category(ACT_ATTACK);

  script_tag(name:"qod_type", value:"exploit");
  script_family("General");
  script_tag(name:"solution_type", value:"VendorFix");

  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_codesys_detect.nasl");
  script_mandatory_keys("codesys/detected");

  script_tag(name:"summary", value:"The Runtime Toolkit in CODESYS Runtime System 2.3.x and 2.4.x does not
require authentication, which allows remote attackers to execute commands via the command-line interface in the
TCP listener service or transfer files via requests to the TCP listener service. (CVE-2012-6068)

The CoDeSys Runtime Toolkit's file transfer functionality does not perform input validation, which allows an
attacker to access files and directories outside the intended scope. This allows an attacker to upload and
download any file on the device. This could allow the attacker to affect the availability, integrity, and
confidentiality of the device. (CVE-2012-6069)");
  script_tag(name:"solution", value:"Update to the latest available version.");

  exit(0);
}

include("byte_func.inc");
include("dump.inc");
include("misc_func.inc");

port = get_port_for_service(default: 2455, proto: "codesys");
soc = open_sock_tcp(port);
if (!soc)
  exit(0);

# based on https://github.com/digitalbond/Basecamp/blob/master/codesys-shell.py
cmd = raw_string(0x92, 0x00, 0x00, 0x00, 0x00, '?', 0x00);
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
cmd_len_little = mkword(strlen(cmd));
set_byte_order(BYTE_ORDER_BIG_ENDIAN);
cmd_len_big = mkword(strlen(cmd));

lile_query = raw_string(0xcc, 0xcc, 0x01, 0x00, cmd_len_little, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x23, cmd_len_little, 0x00, cmd);
bige_query = raw_string(0xcc, 0xcc, 0x01, 0x00, cmd_len_big, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x23, cmd_len_big, 0x00, cmd);

send(socket: soc, data: lile_query);
recv = recv(socket: soc, length: 512);

if (!recv) {
  send(socket: soc, data: bige_query);
  recv = recv(socket: soc, length: 512);
  if (!recv) {
    close(soc);
    exit(99);
  }
}

close(soc);

if (hexstr(substr(recv, 0, 1)) == "cccc" && "show implemented commands" >< recv) {
  report = "It was possible to access the CODESYS Runtime System without authentication.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
