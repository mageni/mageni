###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_storageworks_51399.nasl 13568 2019-02-11 10:22:27Z cfischer $
#
# HP StorageWorks Default Accounts and Directory Traversal Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103431");
  script_bugtraq_id(51399);
  script_cve_id("CVE-2011-4788", "CVE-2012-0697");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13568 $");
  script_name("HP StorageWorks Default Accounts and Directory Traversal Vulnerabilities");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-02-21 13:19:06 +0100 (Tue, 21 Feb 2012)");

  script_xref(name:"URL", value:"http://h10010.www1.hp.com/wwpc/us/en/sm/WF05a/12169-304616-241493-241493-241493-3971478.html");
  script_xref(name:"URL", value:"http://www.compaq.com/storage/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-015/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/885499");

  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "ssh_detect.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/www", 80, "Services/ssh", 22, "Services/telnet", 23);
  script_mandatory_keys("WindRiver-WebServer/banner");

  script_tag(name:"impact", value:"An attacker could exploit these issues to access arbitrary files on
 the affected computer, or gain administrative access to the affected application. This may aid in
 the compromise of the underlying computer.");
  script_tag(name:"affected", value:"HP StorageWorks P2000 G3 is affected.");
  script_tag(name:"solution", value:"The vendor released an update to address this issue. Please see the
 references for more information.");
  script_tag(name:"summary", value:"HP StorageWorks is prone to a security-bypass vulnerability and a directory-
 traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "WindRiver-WebServer" >!< banner)
  exit(0);

buf = http_get_cache(item:"/", port:port);

if("<title>HP StorageWorks" >< buf) {

  credentials = make_array('monitor', '!monitor','manage', '!manage','ftp', '!ftp');

  port = get_ssh_port(default:22);
  foreach credential (keys(credentials)) {

    if(!soc = open_sock_tcp(port))
      break;

    user = credential;
    pass = credentials[credential];

    login = ssh_login (socket:soc, login:user, password:pass, pub:NULL, priv:NULL, passphrase:NULL);

    if(login == 0) {
      report = 'It was possible to login via ssh using "' + user + '" as username and "' + pass + '" as password.\n';
      security_message(port:port, data:report);
      close(soc);
      exit(0);
    }
    close(soc);
  }

  port = get_telnet_port(default:23);
  foreach credential (keys(credentials)) {

    if(!soc = open_sock_tcp(port))
      break;

    user = credential;
    pass = credentials[credential];

    b = telnet_negotiate(socket:soc);

    if("Login" >!< b)break;

    send(socket:soc,data:string(user,"\r\n"));
    answer = recv(socket:soc, length:4096);

    send(socket:soc, data:string(pass,"\r\n"));
    answer = recv(socket:soc, length:4096);

    if("StorageWorks" >< answer && "System Name" >< answer) {
      report = 'It was possible to login via telnet using "' + user + '" as username and "' + pass + '" as password.\n';
      security_message(port:port, data:report);
      close(soc);
      exit(0);
    }
    close(soc);
  }
  exit(99);
}

exit(0);