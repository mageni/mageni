# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826506");
  script_version("2022-09-14T10:57:19+0000");
  script_cve_id("CVE-2022-32868", "CVE-2022-32886", "CVE-2022-32912", "CVE-2022-32891");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-14 10:57:19 +0000 (Wed, 14 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-13 12:00:53 +0530 (Tue, 13 Sep 2022)");
  script_name("Apple Safari Security Update (HT213442)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An improper UI handling.

  - An out-of-bounds read issue due to improper bounds checking.

  - A buffer overflow issue due to an improper memory handling.

  - A logic issue due to an improper state management.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow attackers to execute arbitrary code and conduct spoofing attack.");

  script_tag(name:"affected", value:"Apple Safari versions before 16");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 16 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213442");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");
include("host_details.inc");

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^1[12]\."){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
safVer = infos['version'];
safPath = infos['location'];

if(version_is_less(version:safVer, test_version:"16"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"16", install_path:safPath);
  security_message(data:report);
  exit(0);
}
exit(0);
