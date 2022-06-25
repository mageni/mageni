###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes Security Updates (HT209450)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814822");
  script_version("2019-05-22T13:05:41+0000");
  script_cve_id("CVE-2018-20346", "CVE-2018-20505", "CVE-2019-6212", "CVE-2019-6215",
                "CVE-2019-6216", "CVE-2019-6221", "CVE-2019-6227", "CVE-2019-6229",
                "CVE-2019-6233", "CVE-2018-20506", "CVE-2019-6217", "CVE-2019-6234",
                "CVE-2019-6235", "CVE-2019-6226");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-22 13:05:41 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-01-25 14:09:57 +0530 (Fri, 25 Jan 2019)");
  script_name("Apple iTunes Security Updates (HT209450)");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple memory corruption issues.

  - An out-of-bounds read error.

  - A type confusion issue.

  - A logic issue.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to elevate
  privileges, conduct universal cross site scripting and execute arbitrary code.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.9.3");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.9.3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209450");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
appVer = infos['version'];
appPath = infos['location'];

if(version_is_less(version:appVer, test_version:"12.9.3"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"12.9.3", install_path: appPath);
  security_message(data:report);
  exit(0);
}
exit(99);
