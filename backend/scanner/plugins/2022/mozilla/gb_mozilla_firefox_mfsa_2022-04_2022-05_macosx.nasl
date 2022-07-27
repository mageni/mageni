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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819994");
  script_version("2022-02-22T06:48:08+0000");
  script_cve_id("CVE-2022-22754", "CVE-2022-22755", "CVE-2022-22756", "CVE-2022-22757",
                "CVE-2022-22759", "CVE-2022-22760", "CVE-2022-22761", "CVE-2022-22764",
                "CVE-2022-0511");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-02-22 11:21:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-10 09:39:02 +0530 (Thu, 10 Feb 2022)");
  script_name("Mozilla Firefox Security Update(mfsa_2022-04_2022-05) - MAC OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Extensions could have bypassed permission confirmation during update.

  - XSL could have allowed JavaScript execution after a tab was closed.

  - Drag and dropping an image could have resulted in the dropped object being an executable.

  - Remote Agent did not prevent local websites from connecting.

  - Sandboxed iframes could have executed script if the parent appended elements.

  - Cross-Origin responses could be distinguished between script and non-script content-types.

  - frame-ancestors Content Security Policy directive was not enforced for framed extension pages.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  escalate privileges, bypass permissions and conduct javascript execution.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  97 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 97
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-04/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"97"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"97", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
