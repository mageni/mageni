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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814861");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-18356", "CVE-2019-5785", "CVE-2018-18335", "CVE-2018-18509");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-02-18 10:53:14 +0530 (Mon, 18 Feb 2019)");
  script_name("Mozilla Thunderbird Security Updates(mfsa2019-06)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A use-after-free vulnerability in the Skia library.

  - An integer overflow vulnerability in the Skia library.

  - A buffer overflow vulnerability in the Skia library.

  - A flaw during verification of certain S/MIME signatures.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  crash the application and craft email messages with arbitrary content.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 60.5.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 60.5.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-06/");
  script_xref(name:"URL", value:"https://www.thunderbird.net/en-US");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"60.5.1"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"60.5.1", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
exit(99);
