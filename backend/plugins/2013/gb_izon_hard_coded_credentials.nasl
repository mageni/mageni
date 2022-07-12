###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_izon_hard_coded_credentials.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# IZON IP Cameras Hard-coded Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103824");
  script_version("$Revision: 13624 $");
  script_cve_id("CVE-2013-6236");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IZON IP Cameras Hard-coded Credentials");
  script_xref(name:"URL", value:"https://blog.duosecurity.com/2013/10/izon-ip-camera-hardcoded-passwords-and-unencrypted-data-abound/");
  script_xref(name:"URL", value:"https://securityledger.com/2013/10/apple-store-favorite-izon-cameras-riddled-with-security-holes/");

  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-11-07 11:02:55 +0200 (Thu, 07 Nov 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/izon/ip_camera/detected");

  script_tag(name:"impact", value:"Attackers can exploit these issues to gain unauthorized access to the
  affected device and perform certain administrative actions.");

  script_tag(name:"vuldetect", value:"Start a telnet session with the hard-coded credentials.");

  script_tag(name:"insight", value:"A user can login to the Telnet service (also with root privileges) using the
  hard-coded credentials:

  root:stemroot

  admin:/ADMIN/

  mg3500:merlin");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The remote IZON IP Camera is prone to a hard-coded credentials bypass
  vulnerability");

  exit(0);
}

include("telnet_func.inc");

port = get_telnet_port(default:23);
banner = get_telnet_banner(port:port);
if(!banner || "izon login" >!< banner)
  exit(0);

up = make_array("root","stemroot","admin","/ADMIN/","mg3500","merlin");

foreach login (keys(up)) {

  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  recv(socket:soc, length:1024);

  send(socket:soc, data:login + '\r\n');
  recv = recv(socket:soc, length:512);
  if("Password:" >!< recv)continue;

  send(socket:soc, data: up[login] + '\r\n');
  while(recv = recv(socket:soc, length:1024)) x++;

  send(socket:soc, data: 'id\r\n');
  recv = recv(socket:soc, length:512);

  close(soc);

  if(recv =~ 'uid=[0-9]+.*gid=[0-9]+') {
    security_message(port:port, data: 'It was possible to login with username "' + login + '" using password "' + up[login] + '"\n');
    exit(0);
  }
}

exit(99);