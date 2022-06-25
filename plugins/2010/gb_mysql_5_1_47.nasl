###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_5_1_47.nasl 11830 2018-10-11 06:12:56Z cfischer $
#
# MySQL < 5.1.47 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100657");
  script_version("$Revision: 11830 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 08:12:56 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2010-05-27 12:50:36 +0200 (Thu, 27 May 2010)");
  script_bugtraq_id(40100, 40109);
  script_cve_id("CVE-2010-1849", "CVE-2010-1848");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("MySQL < 5.1.47 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40109");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-47.html");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=50974");
  script_xref(name:"URL", value:"http://www.mysql.com/");

  script_tag(name:"summary", value:"MySQL < 5.1.47 is prone to multiple vulnerabilities.");

  script_tag(name:"impact", value:"1. A remote denial-of-service vulnerability.

  Attackers can exploit this issue to cause the application to end up in
  a locked server state, denying service to legitimate users.

  2. A security-bypass vulnerability.

  An attacker can exploit this issue to bypass certain security
  restrictions and to read and delete content from the affected
  database. Other attacks may also be possible.");

  script_tag(name:"affected", value:"Versions prior to MySQL 5.1.47 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!ver = get_app_version(cpe:CPE, port:port)) exit(0);

if(ver =~ "^5\.1\." && version_is_less(version:ver, test_version:"5.1.47")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"5.1.47");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);