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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817556");
  script_version("2020-12-22T06:30:14+0000");
  script_cve_id("CVE-2020-16042", "CVE-2020-26971", "CVE-2020-26973", "CVE-2020-26974",
                "CVE-2020-26978", "CVE-2020-35111", "CVE-2020-35112", "CVE-2020-35113");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-12-22 06:30:14 +0000 (Tue, 22 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-16 11:17:05 +0530 (Wed, 16 Dec 2020)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2020-54_2020-56)-Windows");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Operations on a BigInt could have caused uninitialized memory to be exposed.

  - Heap buffer overflow in WebGL.

  - CSS Sanitizer performed incorrect sanitization.

  - Incorrect cast of StyleGenericFlexBasis resulted in a heap use-after-free.

  - Internal network hosts could have been probed by a malicious webpage.

  - The proxy.onRequest API did not catch view-source URLs.

  - Opening an extension-less download may have inadvertently launched an executable instead.

  - Memory safety bugs fixed in Firefox 84 and Firefox ESR 78.6.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct a denial-of-service, execute arbitrary code or information disclosure
  on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  78.6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 78.6
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-55/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"78.6"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"78.6", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
