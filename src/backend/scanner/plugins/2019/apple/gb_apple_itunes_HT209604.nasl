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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814875");
  script_version("2019-05-22T13:05:41+0000");
  script_cve_id("CVE-2019-8542", "CVE-2019-8506", "CVE-2019-8535", "CVE-2019-6201",
                "CVE-2019-8518", "CVE-2019-8523", "CVE-2019-8524", "CVE-2019-8558",
                "CVE-2019-8559", "CVE-2019-8563", "CVE-2019-8515", "CVE-2019-8536",
                "CVE-2019-8544", "CVE-2019-7285", "CVE-2019-8556", "CVE-2019-8503",
                "CVE-2019-8562", "CVE-2019-7292", "CVE-2019-8551");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-22 13:05:41 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-03-26 10:32:20 +0530 (Tue, 26 Mar 2019)");
  script_name("Apple iTunes Security Updates (HT209604)");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A buffer overflow error,

  - A type confusion error,

  - Multiple memory corruption issues,

  - A cross-origin issue with the fetch API,

  - A use after free error,

  - A logic issue and

  - A validation issue.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to elevate privileges, execute scripts, circumvent
  sandbox restrictions, execute arbitrary code, read sensitive user information
  and process memory, conduct universal cross site scripting by processing
  maliciously crafted web content.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.9.4");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.9.4 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209604");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ituneVer = infos['version'];
itunePath = infos['location'];

if(version_is_less(version:ituneVer, test_version:"12.9.4"))
{
  report = report_fixed_ver(installed_version: ituneVer, fixed_version:"12.9.4", install_path: itunePath);
  security_message(data:report);
  exit(0);
}
exit(99);
