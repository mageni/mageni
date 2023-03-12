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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832017");
  script_version("2023-03-03T10:59:40+0000");
  script_cve_id("CVE-2023-0616", "CVE-2023-25728", "CVE-2023-25730", "CVE-2023-0767",
                "CVE-2023-25735", "CVE-2023-25737", "CVE-2023-25739", "CVE-2023-25746",
                "CVE-2023-25729", "CVE-2023-25732", "CVE-2023-25742");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-03-03 10:59:40 +0000 (Fri, 03 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-03 11:48:39 +0530 (Fri, 03 Mar 2023)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2023-05_2023-07)-MAC OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - User Interface lockup with messages combining S/MIME and OpenPGP.

  - Content security policy leak in violation reports using iframes.

  - Screen hijack via browser fullscreen mode.

  - Potential use-after-free from compartment mismatch in SpiderMonkey.

  - Invalid downcast in SVGUtils::SetupStrokeGeometry.

  - Use-after-free in mozilla::dom::ScriptLoadContext::~ScriptLoadContext.

  - Extensions could have opened external schemes without user knowledge.

  - Out of bounds memory write from EncodeInputStream.

  - Web Crypto ImportKey crashes tab.

  - Arbitrary memory write via PKCS 12 in NSS.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  disclose sensitive information, execute arbitrary code and cause denial of
  service condition.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 102.8 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 102.8
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-07/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
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

if(version_is_less(version:tbVer, test_version:"102.8"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"102.8", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
