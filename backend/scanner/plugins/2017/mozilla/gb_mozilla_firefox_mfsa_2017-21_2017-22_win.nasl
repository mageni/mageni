###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mfsa_2017-21_2017-22_win.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Mozilla Firefox Security Updates( mfsa_2017-21_2017-22 )-Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811848");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-7793", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7824",
                "CVE-2017-7805", "CVE-2017-7812", "CVE-2017-7814", "CVE-2017-7813",
                "CVE-2017-7815", "CVE-2017-7816", "CVE-2017-7821", "CVE-2017-7823",
                "CVE-2017-7822", "CVE-2017-7820", "CVE-2017-7811", "CVE-2017-7810");
  script_bugtraq_id(101055, 101053, 101059, 101057, 101054);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-03 15:33:22 +0530 (Tue, 03 Oct 2017)");
  script_name("Mozilla Firefox Security Updates( mfsa_2017-21_2017-22 )-Windows");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,

  - Use-after-free error with Fetch API.

  - Firefox for Android address bar spoofing through full screen mode.

  - Use-after-free error during ARIA array manipulation.

  - Use-after-free error while resizing images in design mode.

  - Buffer overflow error when drawing and validating elements with ANGLE.

  - Use-after-free error in TLS 1.2 generating handshake hashes.

  - Drag and drop of malicious page content to the tab bar can open locally stored files.

  - Blob and data URLs bypass phishing and malware protection warnings.

  - Integer truncation in the JavaScript parser.

  - OS X fonts render some Tibetan and Arabic unicode characters as spaces.

  - Spoofing attack with modal dialogs on non-e10s installations.

  - Web Extensions can load about: URLs in extension UI.

  - Web Extensions can download and open non-executable files without user interaction.

  - CSP sandbox directive did not create a unique origin.

  - Web Crypto allows AES-GCM with 0-length IV.

  - Xray wrapper bypass with new tab and web console.

  - Memory safety bugs fixed in Firefox 56.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to cause denial of service, conduct
  spoofing attack, obtain sensitive information and execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  56.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 56.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-21");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"56.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"56.0", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(99);