###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gogs_multiple_vuln.nasl 12326 2018-11-13 05:25:34Z ckuersteiner $
#
# Gogs Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:gogs:gogs';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105952");
  script_version("$Revision: 12326 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 06:25:34 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-02-06 14:11:04 +0700 (Fri, 06 Feb 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-8681", "CVE-2014-8682", "CVE-2014-8683");
  script_bugtraq_id(71188, 71187, 71186);

  script_name("Gogs Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_dependencies("gb_gogs_detect.nasl");
  script_mandatory_keys("gogs/detected");

  script_tag(name:"summary", value:"Gogs (Go Git Service) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The installed Gogs version is prone to the following vulnerabilities:

  CVE-2014-8681:
  SQL injection vulnerability in the GetIssues function in models/issue.go.

  CVE-2014-8682:
  Multiple SQL injection vulnerabilities in the q parameter of api/v1/repos/search, which is not properly handled in models/repo.go and in api/v1/users/search, which is not properly handled in models/user.go.

  CVE-2014-8683:
  Cross-site scripting (XSS) vulnerability in models/issue.go.");

  script_tag(name:"impact", value:"Unauthenicated attackers can exploit this vulnerabilities to perform
  an XSS attack or execute arbitrary SQL commands which may lead to a complete compromise of the database.");

  script_tag(name:"affected", value:"Gogs (aka Go Git Service) 0.3.1-9 through 0.5.x before 0.5.8");

  script_tag(name:"solution", value:"Update to version 0.5.8 or later.");

  script_xref(name:"URL", value:"http://gogs.io/docs/intro/change_log.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129116/Gogs-Label-Search-Blind-SQL-Injection.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129117/Gogs-Repository-Search-SQL-Injection.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129118/Gogs-Markdown-Renderer-Cross-Site-Scripting.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.5.8");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
