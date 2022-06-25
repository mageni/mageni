# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815183");
  script_version("2019-07-18T05:45:58+0000");
  script_cve_id("CVE-2019-2745");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-07-18 05:45:58 +0000 (Thu, 18 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-17 13:09:32 +0530 (Wed, 17 Jul 2019)");
  script_name("Oracle Java SE Security Updates (jul2019-5072835) 05 - Windows");

  script_tag(name:"summary", value:"The host is installed with Oracle Java SE
  and is prone to a security vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exist due to error in 'Security'
  component.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.7.0 to 1.7.0.221,
  1.8.0 to 1.8.0.212 and 11.0 to 11.0.3 on Windows");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/java/javase/downloads/index.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE))
{
  CPE = "cpe:/a:oracle:jdk";
  if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
}

jreVer = infos['version'];
path = infos['location'];

if(!jreVer){
  exit(0);
}

if(version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.221")||
  version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.212")||
  version_in_range(version:jreVer, test_version:"11.0", test_version2:"11.0.3"))
{
  report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
