# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.815893");
  script_version("2020-01-17T10:38:45+0000");
  script_cve_id("CVE-2019-17026", "CVE-2019-17015", "CVE-2019-17016", "CVE-2019-17017",
                "CVE-2019-17021", "CVE-2019-17022", "CVE-2019-17024");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-17 10:38:45 +0000 (Fri, 17 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-14 15:15:54 +0530 (Tue, 14 Jan 2020)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2020-04)-Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An incorrect alias information in IonMonkey JIT compiler for setting array
    elements.

  - Memory corruption error in parent process during new content process
    initialization.

  - Bypass of @namespace CSS sanitization during pasting.

  - Type Confusion error in XPCVariant.cpp due to a missing case handling
    object types.

  - Heap address disclosure in parent process during content process initialization.

  - CSS sanitization does not escape HTML tags.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  disclose sensitive information, run arbitrary code and crash the affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  68.4.1 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 68.4.1
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-04/");
  script_xref(name:"URL", value:"https://www.thunderbird.net");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"68.4.1"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"68.4.1", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
exit(0);
