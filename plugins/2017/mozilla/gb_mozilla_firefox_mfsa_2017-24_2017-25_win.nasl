###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mfsa_2017-24_2017-25_win.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Mozilla Firefox Security Updates(mfsa_2017-24_2017-25)-Windows
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811349");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-7828", "CVE-2017-7830", "CVE-2017-7831", "CVE-2017-7832",
		"CVE-2017-7833", "CVE-2017-7834", "CVE-2017-7835", "CVE-2017-7836",
		"CVE-2017-7837", "CVE-2017-7838", "CVE-2017-7839", "CVE-2017-7840",
		"CVE-2017-7842", "CVE-2017-7827", "CVE-2017-7826");
  script_bugtraq_id(101832);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-16 12:41:51 +0530 (Thu, 16 Nov 2017)");
  script_name("Mozilla Firefox Security Updates(mfsa_2017-24_2017-25)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,

  - Use-after-free of PressShell while restyling layout.

  - Cross-origin URL information leak through Resource Timing API.

  - Information disclosure of exposed properties on JavaScript proxy objects.

  - Domain spoofing through use of dotless character followed by accent markers.

  - Domain spoofing with Arabic and Indic vowel marker characters.

  - data: URLs opened in new tabs bypass CSP protections.

  - Mixed content blocking incorrectly applies with redirects.

  - Pingsender dynamically loads libcurl on Linux and OS X.

  - SVG loaded can use meta tags to set cookies.

  - Failure of individual decoding of labels in international domain names triggers
    punycode display of entire IDN.

  - Control characters before javascript: URLs defeats self-XSS prevention mechanism.

  - Exported bookmarks do not strip script elements from user-supplied tags.

  - Referrer Policy is not always respected for elements.

  - Memory safety bugs fixed in Firefox 57.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  to execute arbitrary code, bypass security restrictions, perform unauthorized
  actions, and obtain sensitive information. Failed exploit attempts will likely
  result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 57.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 57.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-24/");
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

if(version_is_less(version:ffVer, test_version:"57.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"57.0", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(99);