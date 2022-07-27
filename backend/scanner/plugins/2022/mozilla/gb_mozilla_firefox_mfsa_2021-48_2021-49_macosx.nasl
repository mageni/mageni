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
  script_oid("1.3.6.1.4.1.25623.1.0.820043");
  script_version("2022-03-31T07:10:52+0000");
  script_cve_id("CVE-2021-38503", "CVE-2021-38504", "CVE-2021-43533", "CVE-2021-38506",
                "CVE-2021-38507", "CVE-2021-43534", "CVE-2021-38508", "CVE-2021-43531",
                "CVE-2021-43532", "CVE-2021-38509", "CVE-2021-38510");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-28 16:56:01 +0530 (Mon, 28 Mar 2022)");
  script_name("Mozilla Firefox Security Update (mfsa_2021-48_2021-49) - MAC OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - iframe sandbox rules did not apply to XSLT stylesheets.

  - Use-after-free in file picker dialog.

  - Firefox could be coaxed into going into fullscreen mode without notification or warning.

  - Opportunistic Encryption in HTTP2 could be used to bypass the Same-Origin-Policy on services hosted on other ports.

  - Permission Prompt could be overlaid, resulting in user confusion and potential spoofing.

  - Web Extensions could access pre-redirect URL when their context menu was triggered by a user.

  - Javascript alert box could have been spoofed onto an arbitrary domain.

  - Download Protections were bypassed by .inetloc files on Mac OS.

  - 'Copy Image Link' context menu action could have been abused to see authentication tokens.

  - URL Parsing may incorrectly parse internationalized domains.

  - Memory safety bugs fixed in Firefox 94 and Firefox ESR 91.3.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service, bypass authentication
  and conduct spoofing attack, etc.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  94 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 94
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-48/");
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
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"94"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"94", install_path:path);
  security_message(data:report);
  exit(0);
}
