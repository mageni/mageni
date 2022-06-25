###############################################################################
# OpenVAS Vulnerability Test
#
# MariaDB Denial Of Service Vulnerability (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804035");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2013-1861");
  script_bugtraq_id(58511);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2013-10-28 19:18:10 +0530 (Mon, 28 Oct 2013)");
  script_name("MariaDB Denial Of Service Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52639");
  script_xref(name:"URL", value:"https://mariadb.atlassian.net/browse/MDEV-4252");
  script_xref(name:"URL", value:"http://lists.askmonty.org/pipermail/commits/2013-March/004371.html");

  script_tag(name:"summary", value:"This host is installed with MariaDB and is prone to denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to MariaDB 5.1.68, 5.2.15, 5.3.13, 5.5.30 or later.");

  script_tag(name:"insight", value:"Numeric calculation error occurs due to an improper handling of geometry
  feature while converting a binary string representation of a raw geometry
  object to a textual representation.");

  script_tag(name:"affected", value:"MariaDB version 5.5.x before 5.5.30, 5.3.x before 5.3.13,
  5.2.x before 5.2.15, and 5.1.x before 5.1.68 on Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to crash the program
  via a crafted geometry feature that specifies a large number of points.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!mariadbPort = get_app_port(cpe:CPE)){
  exit(0);
}

mariadbVer = get_app_version(cpe:CPE, port:mariadbPort);
if(!mariadbVer || mariadbVer !~ "^5\.[1235]\."){
  exit(0);
}

if(version_in_range(version:mariadbVer, test_version:"5.1", test_version2:"5.1.67") ||
   version_in_range(version:mariadbVer, test_version:"5.2", test_version2:"5.2.14") ||
   version_in_range(version:mariadbVer, test_version:"5.3", test_version2:"5.3.12") ||
   version_in_range(version:mariadbVer, test_version:"5.5", test_version2:"5.5.29"))
{
  fix = "5.1.68, or 5.2.15, or 5.3.13, or 5.5.30";
  report = report_fixed_ver(installed_version:mariadbVer, fixed_version:fix);
  security_message(port:mariadbPort, data:report);
  exit(0);
}

exit(99);