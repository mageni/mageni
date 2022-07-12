###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_gcm_kvm_default_login.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# IBM GCM16/GCM32 Default Login
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
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103763");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-08-19 11:03:03 +0100 (Mon, 19 Aug 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("IBM GCM16/GCM32 Default Login");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_gcm_kvm_webinterface_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("GCM_16_32/web/installed", "GCM_16_32/web/port");

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain access to
sensitive information or modify system configuration without requiring authentication.');
  script_tag(name:"vuldetect", value:'This check tries to login into the remote KVM as Admin.');
  script_tag(name:"insight", value:'It was possible to login with username "Admin" and an empty password.');
  script_tag(name:"solution", value:'Set a password.');
  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"summary", value:'The remote IBM GCM16 or GCM32 KVM is prone to a default account
authentication bypass vulnerability.');

  exit(0);
}

include("http_func.inc");

port = get_kb_item("GCM_16_32/web/port");
if( ! port ) exit( 0 );

useragent = http_get_user_agent();
host = http_host_name(port:port);

req = 'POST /login.php HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept-Encoding: Identity\r\n' +
      'DNT: 1\r\n' +
      'Connection: close\r\n' +
      'Referer: https://' + host + ' /login.php\r\n' +
      'Cookie: avctSessionId=; /home.php-t1s=1\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: 59\r\n' +
      '\r\n' +
      'action=login&loginUsername=Admin&loginPassword=&language=de';

buf = http_send_recv(port:port, data:req);

if("302 Found" >!< buf || "/home.php" >!< buf) exit(0);

session = eregmatch(pattern:"avctSessionId=([0-9]+)", string:buf);

if(isnull(session[1]))exit(0);

avctSessionId = session[1];

req = 'GET /home.php HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Connection: close\r\n' +
      'Accept-Encoding: Identity\r\n' +
      'Accept-Language:en-us;\r\n' +
      'Cookie: avctSessionId=' + avctSessionId + '\r\n\r\n';

buf = http_send_recv(port:port, data:req);

if("<b>Admin</b>" >< buf && "/appliance-overview.php" >< buf && "/logout.php" >< buf) {
  security_message(port:port);
  exit(0);
}

exit(99);