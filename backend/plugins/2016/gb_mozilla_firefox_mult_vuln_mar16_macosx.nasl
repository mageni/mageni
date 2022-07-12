###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln_mar16_macosx.nasl 11903 2018-10-15 10:26:16Z asteins $
#
# Mozilla Firefox Multiple Vulnerabilities - Mar16 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807521");
  script_version("$Revision: 11903 $");
  script_cve_id("CVE-2016-1954", "CVE-2016-1955", "CVE-2016-1957", "CVE-2016-1958",
                "CVE-2016-1959", "CVE-2016-1960", "CVE-2016-1950", "CVE-2016-1952",
                "CVE-2016-1953", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1963",
                "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1967",
                "CVE-2016-1968", "CVE-2016-1969", "CVE-2016-1973", "CVE-2016-1974",
                "CVE-2016-1977", "CVE-2016-1979", "CVE-2016-2790", "CVE-2016-2791",
                "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795",
                "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799",
                "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 12:26:16 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-14 18:18:51 +0530 (Mon, 14 Mar 2016)");
  script_name("Mozilla Firefox Multiple Vulnerabilities - Mar16 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The 'nsCSPContext::SendReports' function in 'dom/security/nsCSPContext.cpp'
    script does not prevent use of a non-HTTP report-uri for a CSP violation
    report.

  - The CSP violation reports contained full path information for cross-origin
    iframe navigations in violation of the CSP specification.

  - A memory leak in the libstagefright library when array destruction occurs
    during MPEG4 video file processing.

  - An error in 'browser/base/content/browser.js' script.

  - Multiple use-after-free issues.

  - Multiple out-of-bounds read errors

  - A memory corruption vulnerability in the FileReader class.

  - The mishandling of a navigation sequence that returns to the original page.

  - Improper restriction of the availability of IFRAME Resource Timing API times.

  - Integer underflow in Brotli library's decompression.

  - A memory corruption issue in NPAPI plugin in 'nsNPObjWrapper::GetNewOrUsed'
    function in 'dom/plugins/base/nsJSNPRuntime.cpp' script.

  - A race condition in the 'GetStaticInstance' function in the WebRTC
    implementation.

  - Multiple Heap-based buffer overflow vulnerabilities.

  - The multiple unspecified vulnerabilities in the browser engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or to cause a denial of service,
  possibly gain privileges, to bypass the Same Origin Policy, to obtain
  sensitive information and to do spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 45.0 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 45.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-22");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-25");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-19");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"45.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"45.0");
  security_message(data:report);
  exit(0);
}
