###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Java SE Security Updates (jan2018-3236628) 04 - Windows
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812640");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-2634", "CVE-2018-2581");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-01-17 11:41:39 +0530 (Wed, 17 Jan 2018)");
  script_name("Oracle Java SE Security Updates (jan2018-3236628) 04 - Windows");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - An error in the 'JGSS' sub-component of application.

  - An error in the 'JavaFX' sub-component of application.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to access data.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.7.0.161 and earlier,
  1.8.0.152 and earlier, 9.0.1 and earlier on Windows");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
jreVer = infos['version'];
path = infos['location'];

if(jreVer =~ "^((1\.(7|8))|9)")
{
  if(version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.161")||
     version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.152")||
     version_in_range(version:jreVer, test_version:"9.0", test_version2:"9.0.1"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
exit(0);
