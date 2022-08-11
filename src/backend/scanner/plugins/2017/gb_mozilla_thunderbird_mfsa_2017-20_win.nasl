###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_mfsa_2017-20_win.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Mozilla Thunderbird Security Updates( mfsa_2017-20 )-Windows
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811711");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7809", "CVE-2017-7784",
                "CVE-2017-7802", "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7753",
                "CVE-2017-7787", "CVE-2017-7807", "CVE-2017-7792", "CVE-2017-7804",
                "CVE-2017-7791", "CVE-2017-7782", "CVE-2017-7803", "CVE-2017-7779");
  script_bugtraq_id(100196, 100197, 100203, 100202, 100206, 100315, 100234, 100242,
                    100240, 100243, 100201);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-21 11:51:43 +0530 (Mon, 21 Aug 2017)");
  script_name("Mozilla Thunderbird Security Updates( mfsa_2017-20 )-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - Use-after-free in WebSockets during disconnection.

  - Use-after-free with marquee during window resizing.

  - Use-after-free while deleting attached editor DOM node.

  - Use-after-free with image observers.

  - Use-after-free resizing image elements.

  - Buffer overflow manipulating ARIA attributes in DOM.

  - Buffer overflow while painting non-displayable SVG.

  - Out-of-bounds read with cached style data and pseudo-elements.

  - Same-origin policy bypass with iframes through page reloads.

  - Domain hijacking through AppCache fallback.

  - Buffer overflow viewing certificates with an extremely long OID.

  - Memory protection bypass through WindowsDllDetourPatcher.

  - Spoofing following page navigation with data: protocol and modal alerts.

  - WindowsDllDetourPatcher allocates memory without DEP protections.

  - CSP containing sandbox improperly applied.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to gain access to potentially sensitive information,
  execute arbitrary code and conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 52.3
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 52.3.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-20/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!tbVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:tbVer, test_version:"52.3"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"52.3");
  security_message(data:report);
  exit(0);
}

exit(99);
