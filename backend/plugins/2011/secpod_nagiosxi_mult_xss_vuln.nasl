##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nagiosxi_mult_xss_vuln.nasl 12152 2018-10-29 13:35:30Z asteins $
#
# Nagios XI Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902599");
  script_version("$Revision: 12152 $");
  script_bugtraq_id(51069);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 14:35:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-16 10:10:10 +0530 (Fri, 16 Dec 2011)");
  script_name("Nagios XI Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51069");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71825");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71826");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Dec/354");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107872/0A29-11-3.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_mandatory_keys("nagiosxi/installed");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.");
  script_tag(name:"affected", value:"Nagios XI versions prior to 2011R1.9");
  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user-supplied input
  appended to the URL in multiple scripts, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.");
  script_tag(name:"solution", value:"Upgrade to Nagios XI version 2011R1.9 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running Nagios XI and is prone to multiple cross-site
  scripting vulnerabilities.");
  script_xref(name:"URL", value:"http://www.nagios.com/products/nagiosxi");
  exit(0);
}

CPE = "cpe:/a:nagios:nagiosxi";

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";

url = dir + '/login.php/";alert(document.cookie);"';

if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:";alert\(document.cookie\);")) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
