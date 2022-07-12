###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mariadb_dos_vuln_feb17_lin.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# MariaDB Denial Of Service Vulnerability Feb17 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810606");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-3302");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-16 15:44:39 +0530 (Thu, 16 Feb 2017)");
  script_name("MariaDB Denial Of Service Vulnerability Feb17 (Linux)");

  script_tag(name:"summary", value:"This host is running MariaDB and is
  prone to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exists as,

  - In sql-common/client.c script 'mysql_prune_stmt_list' function, the for loop
    adds elements to pruned_list without removing it from the existing list.

  - If application gets disconnected just before it tries to prepare a new
    statement, 'mysql_prune_stmt_list' tries to detach all previously prepared
    statements.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow attackers to cause crash of applications using that MySQL client.");

  script_tag(name:"affected", value:"MariaDB through 5.5.54, 10.0.x through
  10.0.29, 10.1.x through 10.1.21, and 10.2.x through 10.2.3 on Linux");

  script_tag(name:"solution", value:"Update to MariaDB 5.5.55, 10.2.5, 10.1.22, 10.0.30 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/02/11/11");
  script_xref(name:"URL", value:"https://mariadb.org");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_unixoide");
  script_require_ports("Services/mysql", 3306);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!mariadbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mariadbVer = get_app_version(cpe:CPE, port:mariadbPort)){
  exit(0);
}

##10.2.x through 10.2.3
if(mariadbVer =~ "^(10\.2\.)")
{
  if(version_is_less_equal(version:mariadbVer, test_version:"10.2.3"))
  {
    VULN = TRUE;
    fix = "10.2.5";
  }
}

##10.1.x through 10.1.21
else if(mariadbVer =~ "^(10\.1\.)")
{
  if(version_is_less_equal(version:mariadbVer, test_version:"10.1.21"))
  {
    VULN = TRUE;
    fix = "10.1.22";
  }
}

##10.0.x through 10.0.29
else if(mariadbVer =~ "^(10\.0\.)")
{
  if(version_is_less_equal(version:mariadbVer, test_version:"10.0.29"))
  {
    VULN = TRUE;
    fix = "10.0.30";
  }
}

##MariaDB through 5.5.54
else if(version_is_less_equal(version:mariadbVer, test_version:"5.5.54"))
{
  VULN = TRUE;
  fix = "5.5.55";
}

if(VULN)
{
  report = report_fixed_ver(installed_version:mariadbVer, fixed_version:fix);
  security_message(data:report, port:mariadbPort);
  exit(0);
}

exit(0);
