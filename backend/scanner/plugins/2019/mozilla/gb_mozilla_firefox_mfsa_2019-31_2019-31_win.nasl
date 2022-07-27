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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815473");
  script_version("2019-09-20T05:25:28+0000");
  script_cve_id("CVE-2019-11754");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-20 05:25:28 +0000 (Fri, 20 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-19 15:18:57 +0530 (Thu, 19 Sep 2019)");
  script_name("Mozilla Firefox Security Update(mfsa_2019-31_2019-31)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  and is prone to hijacking vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to not giving any user
  notification when the pointer lock is enabled by a website though
  'requestPointerLock' function.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  hijack the mouse pointer and confuse users.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 69.0.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 69.0.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-31");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/new/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"69.0.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"69.0.1", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(0);
