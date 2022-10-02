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
  script_oid("1.3.6.1.4.1.25623.1.0.826479");
  script_version("2022-09-26T10:10:50+0000");
  script_cve_id("CVE-2021-38496", "CVE-2021-38497", "CVE-2021-38498", "CVE-2021-32810",
                "CVE-2021-38500", "CVE-2021-43535", "CVE-2021-38501", "CVE-2021-38499");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-26 10:10:50 +0000 (Mon, 26 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 20:42:00 +0000 (Thu, 04 Nov 2021)");
  script_tag(name:"creation_date", value:"2022-09-22 16:11:07 +0530 (Thu, 22 Sep 2022)");
  script_name("Mozilla Firefox Security Update(mfsa2021-43) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use-after-free in MessageTask.

  - Validation message could have been overlaid on another origin.

  - Use-after-free of nsLanguageAtomService object.

  - Data race in crossbeam-deque.

  - Memory safety bugs.

  - Use-after-free in HTTP2 Session object.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, and leak memory on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  93 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 93
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-43");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"93"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"93", install_path:path);
  security_message(data:report);
  exit(0);
}
