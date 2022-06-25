# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817842");
  script_version("2020-11-19T07:38:10+0000");
  script_cve_id("CVE-2020-26951", "CVE-2020-26952", "CVE-2020-16012", "CVE-2020-26953",
                "CVE-2020-26954", "CVE-2020-26955", "CVE-2020-26956", "CVE-2020-26957",
                "CVE-2020-26958", "CVE-2020-26959", "CVE-2020-26960", "CVE-2020-26968",
                "CVE-2020-26961", "CVE-2020-26962", "CVE-2020-26963", "CVE-2020-26969",
                "CVE-2020-26965", "CVE-2020-26967");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-11-19 11:32:07 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-18 18:51:33 +0530 (Wed, 18 Nov 2020)");
  script_name("Mozilla Firefox Security Updates(mfsa_2020-50_2020-52)-Mac OS X");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Parsing mismatches could confuse and bypass security sanitizer for chrome privileged code.

  - Out of memory handling of JITed, inlined functions could lead to a memory corruption.

  - Variable time processing of cross-origin images during drawImage calls.

  - Fullscreen could be enabled without displaying the security UI.

  - Local spoofing of web manifests for arbitrary pages in Firefox for Android.

  - XSS through paste (manual and clipboard API).

  - OneCRL was not working in Firefox for Android.

  - Requests intercepted through ServiceWorkers lacked MIME type restrictions.

  - Use-after-free in WebRequestService.

  - Potential use-after-free in uses of nsTArray.

  - Heap buffer overflow in freetype.

  - DoH did not filter IPv4 mapped IP Addresses.

  - Cross-origin iframes supported login autofill.

  - History and Location interfaces could have been used to hang the browser.

  - Software keyboards may have remembered typed passwords.

  - Mutation Observers could break or confuse Firefox Screenshots feature.

  - Memory safety bugs fixed.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security, disclose sensitive information and run arbitrary code");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  83 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 83
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-50/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

if(version_is_less(version:ffVer, test_version:"83"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"83", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
