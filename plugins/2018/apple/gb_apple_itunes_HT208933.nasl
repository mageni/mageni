###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes Security Updates(HT208933)-Windows
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813558");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-4293", "CVE-2018-4270", "CVE-2018-4278", "CVE-2018-4284",
                "CVE-2018-4266", "CVE-2018-4261", "CVE-2018-4262", "CVE-2018-4263",
                "CVE-2018-4264", "CVE-2018-4265", "CVE-2018-4267", "CVE-2018-4272",
                "CVE-2018-4271", "CVE-2018-4273");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-10 13:34:53 +0530 (Tue, 10 Jul 2018)");
  script_name("Apple iTunes Security Updates(HT208933)-Windows");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,

  - A cookie management issue in improved checks.

  - A memory corruption issue in memory handling.

  - Sound fetched through audio elements exfiltrated cross-origin.

  - A type confusion issue in memory handling.

  - A race condition in validation.

  - Multiple memory corruption issues in memory handling.

  - Multiple memory corruption issues in input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to crash Safari, exfiltrate audio data cross-origin, execute arbitrary code and
  cause a denial of service.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.8 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.8 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208933");
  script_xref(name:"URL", value:"http://www.apple.com/support");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
ituneVer = infos['version'];
itunePath = infos['location'];

#after installation in registry version 12.8 = 12.8.0.150
if(version_is_less(version:ituneVer, test_version:"12.8.0.150"))
{
  report = report_fixed_ver(installed_version:ituneVer, fixed_version:"12.8", install_path:itunePath);
  security_message(data:report);
  exit(0);
}
exit(0);
