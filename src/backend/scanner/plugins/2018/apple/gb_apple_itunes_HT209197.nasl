###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes Multiple Vulnerabilities-HT209197 (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.814321");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-4398", "CVE-2018-4394", "CVE-2018-4374", "CVE-2018-4377",
                "CVE-2018-4372", "CVE-2018-4373", "CVE-2018-4375", "CVE-2018-4376",
                "CVE-2018-4382", "CVE-2018-4386", "CVE-2018-4392", "CVE-2018-4416",
                "CVE-2018-4409", "CVE-2018-4378");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-31 10:56:19 +0530 (Wed, 31 Oct 2018)");
  script_name("Apple iTunes Multiple Vulnerabilities-HT209197 (Windows)");

  script_tag(name:"summary", value:"This host is running Apple iTunes and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An issue in the method for determining prime numbers.

  - A logic issue due to improper validation.

  - A cross-site scripting issue due to improper URL validation.

  - A resource exhaustion issue due to improper input validation.

  - Multiple memory corruption issues due to poor memory handling and improper
    input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct cross site scripting and arbitrary code execution.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.9.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.9.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209197");
  script_xref(name:"URL", value:"https://www.apple.com/");
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
appVer = infos['version'];
appPath = infos['location'];

#12.9.1=12.9.1.4
if(version_is_less(version:appVer, test_version:"12.9.1.4"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"12.9.1.4", install_path: appPath);
  security_message(data:report);
  exit(0);
}
