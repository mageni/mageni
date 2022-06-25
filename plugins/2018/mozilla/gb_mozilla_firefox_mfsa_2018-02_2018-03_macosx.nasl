###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mfsa_2018-02_2018-03_macosx.nasl 12068 2018-10-25 07:21:15Z mmartin $
#
# Mozilla Firefox Security Updates( mfsa_2018-02_2018-03 )-MAC OS X
#
# Authors:
# Shakeel <bshakeeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812669");
  script_version("$Revision: 12068 $");
  script_cve_id("CVE-2018-5091", "CVE-2018-5092", "CVE-2018-5093", "CVE-2018-5094",
                "CVE-2018-5095", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099",
                "CVE-2018-5100", "CVE-2018-5101", "CVE-2018-5102", "CVE-2018-5103",
                "CVE-2018-5104", "CVE-2018-5105", "CVE-2018-5106", "CVE-2018-5107",
                "CVE-2018-5108", "CVE-2018-5109", "CVE-2018-5110", "CVE-2018-5111",
                "CVE-2018-5112", "CVE-2018-5113", "CVE-2018-5114", "CVE-2018-5115",
                "CVE-2018-5116", "CVE-2018-5117", "CVE-2018-5118", "CVE-2018-5119",
                "CVE-2018-5121", "CVE-2018-5122", "CVE-2018-5090", "CVE-2018-5089");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 09:21:15 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-24 12:35:29 +0530 (Wed, 24 Jan 2018)");
  script_name("Mozilla Firefox Security Updates( mfsa_2018-02_2018-03 )-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple Use-after-free errors, buffer overflow errors, memory safety bugs
    and integer overflow errors.

  - WebExtensions can save and execute files on local file system without user prompts.

  - Developer Tools can expose style editor information cross-origin through service worker.

  - Printing process will follow symlinks for local file access.

  - Manually entered blob URL can be accessed by subsequent private browsing tabs.

  - Audio capture prompts and starts with incorrect origin attribution.

  - Cursor can be made invisible on OS X.

  - URL spoofing in addressbar through drag and drop.

  - Extension development tools panel can open a non-relative URL in the panel.

  - WebExtensions can load non-HTTPS pages with browser.identity.launchWebAuthFlow.

  - The old value of a cookie changed to HttpOnly remains accessible to scripts.

  - Background network requests can open HTTP authentication in unrelated foreground tabs.

  - WebExtension ActiveTab permission allows cross-origin frame content access.

  - URL spoofing with right-to-left text aligned left-to-right.

  - Activity Stream images can attempt to load local content through file:.

  - Reader view will load cross-origin content in violation of CORS headers.

  - OS X Tibetan characters render incompletely in the addressbar.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow remote attackers to execute arbitrary code on affected system or
  conduct a denial-of-service condition, gain escalated privileges, gain access
  to sensitive data, conduct phishing attacks, make use of old cookie value,
  get cross-origin frame content access, conduct spoofing and domain name spoofing
  attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 58 on
  MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 58
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-02/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"58"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"58", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(99);
