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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832012");
  script_version("2023-03-03T10:59:40+0000");
  script_cve_id("CVE-2023-25728", "CVE-2023-25730", "CVE-2023-0767", "CVE-2023-25745",
                "CVE-2023-25735", "CVE-2023-25737", "CVE-2023-25739", "CVE-2023-25744",
                "CVE-2023-25729", "CVE-2023-25732", "CVE-2023-25742", "CVE-2023-25741",
                "CVE-2023-25731", "CVE-2023-25733", "CVE-2023-25736");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-03-03 10:59:40 +0000 (Fri, 03 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-03 12:03:00 +0530 (Fri, 03 Mar 2023)");
  script_name("Mozilla Firefox Security Updates(mfsa_2023-04_2023-06)-Windows");

  script_tag(name:"summary", value:"Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Content security policy leak in violation reports using iframes.

  - Screen hijack via browser fullscreen mode.

  - Arbitrary memory write via PKCS 12 in NSS.

  - Potential use-after-free from compartment mismatch in SpiderMonkey.

  - Invalid downcast in SVGUtils::SetupStrokeGeometry.

  - Use-after-free in mozilla::dom::ScriptLoadContext::~ScriptLoadContext.

  - Extensions could have opened external schemes without user knowledge.

  - Out of bounds memory write from EncodeInputStream.

  - Web Crypto ImportKey crashes tab.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, disclose sensitive information and
  conduct spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  110 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 110
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-05/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"110"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"110", install_path:path);
  security_message(data:report);
  exit(0);
}
