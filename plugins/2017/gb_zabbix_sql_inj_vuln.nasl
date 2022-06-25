###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_sql_inj_vuln.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Zabbix SQL Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106613");
  script_version("$Revision: 14175 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-02-20 16:42:02 +0700 (Mon, 20 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-10134");
  script_bugtraq_id(95423);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zabbix SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("zabbix_web_detect.nasl");
  script_mandatory_keys("Zabbix/installed");

  script_tag(name:"summary", value:"Zabbix is prone to a SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SQL injection vulnerability in Zabbix allows remote attackers to execute
  arbitrary SQL commands via the toggle_ids array parameter in latest.php.");

  script_tag(name:"affected", value:"Zabbix version 2.2.x and 3.0.x");

  script_tag(name:"solution", value:"Update to 2.2.14, 3.0.4 or newer versions.");

  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-11023");

  # This vuln is already covered in 1.3.6.1.4.1.25623.1.0.106179 (216/gb_zabbix_sql_inj_vuln.nasl)
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^2\.2") {
  if (version_is_less(version: version, test_version: "2.2.14")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.2.14");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^3\.0") {
  if (version_is_less(version: version, test_version: "3.0.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "3.0.4");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
