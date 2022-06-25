###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_mult_unspecified_vuln01_oct15_win.nasl 12983 2019-01-08 15:30:19Z cfischer $
#
# Oracle MySQL Multiple Unspecified Vulnerabilities-01 Oct15 (Windows)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805764");
  script_version("$Revision: 12983 $");
  script_cve_id("CVE-2015-4913", "CVE-2015-4830", "CVE-2015-4826", "CVE-2015-4815",
                "CVE-2015-4807", "CVE-2015-4802", "CVE-2015-4792", "CVE-2015-4870",
                "CVE-2015-4861", "CVE-2015-4858", "CVE-2015-4836");
  script_bugtraq_id(77153, 77228, 77237, 77222, 77205, 77165, 77171, 77208, 77137,
                    77145, 77190);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 16:30:19 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2015-10-28 13:07:06 +0530 (Wed, 28 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-01 Oct15 (Windows)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors exists in the MySQL Server
  component via unknown vectors related to Server.");

  script_tag(name:"impact", value:"Successful exploitation will allows an
  authenticated remote attacker to affect confidentiality, integrity, and
  availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.5.45 and earlier
  and 5.6.26 and earlier on windows");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(mysqlVer =~ "^5\.[56]\.")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.45")||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.26"))
  {
    report = report_fixed_ver(installed_version:mysqlVer, fixed_version:"Apply the patch", install_path:mysqlPath);
    security_message(data:report, port:sqlPort);
    exit(0);
  }
}

exit(99);