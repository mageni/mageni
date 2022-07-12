###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_multiple_vuln.nasl 11884 2018-10-12 13:33:40Z cfischer $
#
# MySQL multiple Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100356");
  script_version("$Revision: 11884 $");
  script_cve_id("CVE-2009-4028", "CVE-2009-4030");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:33:40 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-11-20 12:35:38 +0100 (Fri, 20 Nov 2009)");
  script_bugtraq_id(37075, 37076);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("MySQL multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37076");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37075");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-41.html");
  script_xref(name:"URL", value:"http://www.mysql.com/");

  script_tag(name:"summary", value:"MySQL is prone to a security-bypass vulnerability and to to a local
  privilege-escalation vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit the security-bypass issue to bypass certain
  security restrictions and obtain sensitive information that may lead to further attacks.

  Local attackers can exploit the local privilege-escalation issue to
  gain elevated privileges on the affected computer.");

  script_tag(name:"affected", value:"Versions prior to MySQL 5.1.41 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!ver = get_app_version(cpe:CPE, port:port)) exit(0);

if(ver =~ "^5\." && version_is_less(version:ver, test_version:"5.1.41")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"5.1.41");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);