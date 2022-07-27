###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle MySQL Security Updates-06 (jul2018-4258247) Linux
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813715");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-3054", "CVE-2018-3077", "CVE-2018-3056", "CVE-2018-3060",
                "CVE-2018-3065");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-18 12:35:29 +0530 (Wed, 18 Jul 2018)");
  script_name("Oracle MySQL Security Updates-06 (jul2018-4258247) Linux");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to multiple errors
  in 'Server: DDL', 'Server: Security: Privileges', 'InnoDB' and 'Server: DML'
  components of MySQL Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.7.22 and prior,
  8.0.11 and prior on Linux");

  script_tag(name:"solution", value:"Apply the patch from Reference link.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:sqlPort, exit_no_version:TRUE) ) exit(0);
mysqlVer = infos['version'];
path = infos['location'];

if(version_in_range(version:mysqlVer, test_version:"5.7", test_version2:"5.7.22")||
   version_in_range(version:mysqlVer, test_version:"8.0", test_version2:"8.0.11"))
{
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "Apply the patch");
  security_message(data:report, port:sqlPort);
  exit(0);
}
exit(0);
