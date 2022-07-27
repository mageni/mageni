###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_mfsa_2015-116_2015-133_win.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Mozilla Thunderbird Security Updates( mfsa_2015-116_2015-133 )-Windows
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807635");
  script_version("$Revision: 12338 $");
  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7197",
		"CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200", "CVE-2015-7194",
	        "CVE-2015-7193", "CVE-2015-7189", "CVE-2015-7188", "CVE-2015-4513",
		"CVE-2015-4514");
  script_bugtraq_id(77416, 77415, 77411);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:54 +0530 (Wed, 06 Apr 2016)");
  script_name("Mozilla Thunderbird Security Updates( mfsa_2015-116_2015-133 )-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - An improper handling of the CORS cross-origin request algorithm when
    non-standard Content-Type headers are received.

  - A heap Buffer Overflow in nsJPEGEncoder during image interactions in canvas.

  - An insufficient validation of IP address string.

  - Multiple unspecified vulnerabilities in the browser engine.

  - A buffer overflow vulnerability in the rx::TextureStorage11 class in ANGLE.

  - Lack of status checking in 'AddWeightedPathSegLists' and
    'SVGPathSegListSMILType::Interpolate' functions.

  - Missing status check in CryptoKey interface implementation.

  - A memory corruption vulnerability in libjar through zip files.

  - Memory corruption issues in NSS and NSPR.

  - A heap-based buffer overflow in the ASN.1 decoder in Mozilla (NSS).

  - An integer overflow in the PL_ARENA_ALLOCATE implementation in Mozilla (NSS)");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to bypass security restrictions,
  to execute arbitrary code and to cause denial of service.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  38.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 38.4");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-133/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-132/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-131/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-128/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-127/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-123/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-122/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-116/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/thunderbird");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!tbVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:tbVer, test_version:"38.4"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"38.4");
  security_message(data:report);
  exit(0);
}
