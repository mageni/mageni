###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln01_apr15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Mozilla Firefox Multiple Vulnerabilities-01 Apr15 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805522");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-0816", "CVE-2015-0815", "CVE-2015-0814", "CVE-2015-0812",
                "CVE-2015-0811", "CVE-2015-0808", "CVE-2015-0807", "CVE-2015-0806",
                "CVE-2015-0805", "CVE-2015-0804", "CVE-2015-0803", "CVE-2015-0802",
                "CVE-2015-0801");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-06 13:40:14 +0530 (Mon, 06 Apr 2015)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-01 Apr15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper restriction of resource: URLs.

  - Multiple unspecified errors.

  - No HTTPS session for lightweight theme add-on installations .

  - An out of bounds read error in the QCMS color management library.

  - An incorrect memory management for simple-type arrays in WebRTC.

  - An error in 'navigator.sendBeacon' implementation.

  - Two errors in 'Off Main Thread Compositing' implementation.

  - Two use-after-free errors in 'HTMLSourceElement::AfterSetAttr' function.

  - An error allowing to bypass the Same Origin Policy.

  - Use of docshell type information instead of page principal information for
  'Window.webidl' access control.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary JavaScript code, conduct denial of service
  (memory corruption and application crash) attack, possibly execute arbitrary
  code, conduct DNS spoofing attack and conduct cross-site request forgery
  (CSRF) attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox before version 37.0 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 37.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-33");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-30");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-32");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-34");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-36");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-37");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-38");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-39");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-42");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-40");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"37.0"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "37.0"  + '\n';
  security_message(data:report);
  exit(0);
}
