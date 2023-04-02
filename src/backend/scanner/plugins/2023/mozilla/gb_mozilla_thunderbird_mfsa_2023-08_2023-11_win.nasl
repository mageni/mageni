# Copyright (C) 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826949");
  script_version("2023-03-28T10:09:39+0000");
  script_cve_id("CVE-2023-25751", "CVE-2023-28164", "CVE-2023-28162", "CVE-2023-25752",
                "CVE-2023-28163", "CVE-2023-28176");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-23 17:48:05 +0530 (Thu, 23 Mar 2023)");
  script_name("Mozilla Thunderbird Security Update(mfsa_2023-08_2023-11)-Windows");

  script_tag(name:"summary", value:"Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Incorrect code generation during JIT compilation.

  - URL being dragged from a removed cross-origin iframe into the same tab triggered navigation.

  - Invalid downcast in Worklets.

  - Potential out-of-bounds when accessing throttled streams.

  - Windows Save As dialog resolved environment variables.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service and conduct spoofing.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  102.9 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 102.9
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-11/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102.9"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.9", install_path:path);
  security_message(data:report);
  exit(0);
}
