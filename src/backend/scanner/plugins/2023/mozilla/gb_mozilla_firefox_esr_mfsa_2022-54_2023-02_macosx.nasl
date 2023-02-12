# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826792");
  script_version("2023-01-19T10:10:48+0000");
  script_cve_id("CVE-2022-46871", "CVE-2023-23601", "CVE-2023-23602", "CVE-2022-46877",
                "CVE-2023-23603", "CVE-2023-23605");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-19 10:10:48 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-18 13:24:34 +0530 (Wed, 18 Jan 2023)");
  script_name("Mozilla Firefox ESR Security Update(mfsa_2022-54_2023-02)-MAC OS X");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - libusrsctp library out of date.

  - Malicious command could be hidden in devtools output on Windows.

  - URL being dragged from cross-origin iframe into same tab triggers navigation.

  - Content Security Policy wasn't being correctly applied to WebSockets
    in WebWorkers.

  - Fullscreen notification bypass.

  - Calls to <code>console.log</code> allowed bypassing Content Security Policy
     via format directive.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, disclose sensitive information and
  conduct spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  102.7 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 102.7
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-02/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102.7"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.7", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
