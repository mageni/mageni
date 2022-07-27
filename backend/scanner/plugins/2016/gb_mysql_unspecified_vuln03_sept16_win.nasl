###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln03_sept16_win.nasl 62495 2016-09-12 10:49:47 +0530 Sept$
#
# Oracle MySQL Unspecified Vulnerability-03 Sep16 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809300");
  script_version("2019-05-03T13:51:56+0000");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 13:51:56 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-09-12 13:20:02 +0530 (Mon, 12 Sep 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle MySQL Unspecified Vulnerability-03 Sep16 (Windows)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exist. Please see the references for more information.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  remote attacker to gain elevated privileges on the affected system, also
  could allow buffer overflow attacks.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.5.x to 5.5.51
  on windows");

  script_tag(name:"solution", value:"Upgrade to Oracle MySQL Server 5.5.52 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-52.html");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:mysql:mysql", "cpe:/a:oracle:mysql" );

if(!infos = get_all_app_ports_from_list(cpe_list:cpe_list)) exit( 0 );
CPE = infos['cpe'];
sqlPort = infos['port'];

if(!infos = get_app_version_and_location(cpe:CPE, port:sqlPort, exit_no_version:TRUE)) exit(0);
mysqlVer = infos['version'];
mysqlPath = infos['location'];

if(mysqlVer =~ "^5\.5\.")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.51"))
  {
    report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "5.5.52", install_path:mysqlPath);
    security_message(data:report, port:sqlPort);
    exit(0);
  }
}
