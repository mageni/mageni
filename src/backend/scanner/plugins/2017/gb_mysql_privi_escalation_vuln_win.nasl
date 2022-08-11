###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_privi_escalation_vuln_win.nasl 11959 2018-10-18 10:33:40Z mmartin $
#
# MySQL Privilege Escalation Vulnerability - Windows
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811631");
  script_version("$Revision: 11959 $");
  script_cve_id("CVE-2008-4098");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:33:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-14 17:50:12 +0530 (Mon, 14 Aug 2017)");
  script_name("MySQL Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"This host is running MySQL and is
  prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to table creation option
  allows the use of the MySQL data directory in DATA DIRECTORY and INDEX DIRECTORY
  options.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow an authenticated user to use the DATA DIRECTORY and INDEX DIRECTORY
  options to possibly bypass privilege checks.");

  script_tag(name:"affected", value:"MySQL version before 5.0.67 on Windows");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.0.67.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://bugs.mysql.com/bug.php?id=32167");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){
  exit(0);
}

if(version_is_less(version:mysqlVer, test_version:"5.0.67"))
{
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "5.0.67");
  security_message(data:report, port:sqlPort);
  exit(0);
}
