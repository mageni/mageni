###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_mfsa_2016-62_2016-84_macosx.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Mozilla Firefox Esr Security Updates( mfsa_2016-62_2016-84 )-MAC OS X
#
# Authors:
# kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808643");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-5265", "CVE-2016-5264", "CVE-2016-5263", "CVE-2016-2837",
		"CVE-2016-5262", "CVE-2016-5259", "CVE-2016-5258", "CVE-2016-5254",
		"CVE-2016-5252", "CVE-2016-2836", "CVE-2016-2838", "CVE-2016-2830");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-08 14:55:25 +0530 (Mon, 08 Aug 2016)");
  script_name("Mozilla Firefox Esr Security Updates( mfsa_2016-62_2016-84 )-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox Esr and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - The nsDisplayList::HitTest function mishandles rendering display transformation.

  - The Use-after-free vulnerability in the nsNodeUtils::NativeAnonymousChildListChange
    function.

  - The Use-after-free vulnerability in the WebRTC socket thread.

  - The Use-after-free vulnerability in the CanonicalizeXPCOMParticipant function.

  - The Use-after-free vulnerability in the nsXULPopupManager::KeyDown function.

  - The Stack-based buffer underflow in the mozilla::gfx::BasePoint4d function.

  - The Heap-based buffer overflow in the nsBidi::BracketData::AddOpening function.

  - Multiple unspecified vulnerabilities in the browser enginee.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to bypass the same origin policy, to conduct Universal
  XSS (UXSS) attacks or read arbitrary files, to execute arbitrary code or cause a
  denial of service, to discover cleartext passwords by reading a session restoration
  file and to obtain sensitive information.");

  script_tag(name:"affected", value:"Mozilla Firefox Esr version before 45.x before
  45.3 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox Esr version 45.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-80/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-79/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-78/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-77/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-76/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_in_range(version:ffVer, test_version:"45.0", test_version2:"45.2"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"45.3");
  security_message(data:report);
  exit(0);
}
