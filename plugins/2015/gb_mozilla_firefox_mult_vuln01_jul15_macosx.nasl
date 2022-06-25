###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln01_jul15_macosx.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Mozilla Firefox Multiple Vulnerabilities-01 Jul15 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805906");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-2721", "CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725",
                "CVE-2015-2726", "CVE-2015-2728", "CVE-2015-2729", "CVE-2015-2730",
                "CVE-2015-2731", "CVE-2015-2733", "CVE-2015-2734", "CVE-2015-2735",
                "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738", "CVE-2015-2739",
                "CVE-2015-2740", "CVE-2015-2741", "CVE-2015-2743", "CVE-2015-4000");
  script_bugtraq_id(75541, 74733);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-08 16:47:07 +0530 (Wed, 08 Jul 2015)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-01 Jul15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error within Network Security Services (NSS) where the client allows for
  a 'ECDHE_ECDSA' exchange where the server does not send its 'ServerKeyExchange'
  message.

  - Multiple use-after-free vulnerabilities.

  - Multiple unspecified memory related errors.

  - An error within the 'IndexedDatabaseManager' class in the IndexedDB
  implementation.

  - An error within the 'AudioParamTimeline::AudioNodeInputValue' function in the
  Web Audio implementation .

  - An error in the implementation of Elliptical Curve Cryptography (ECC)
  multiplication for Elliptic Curve Digital Signature Algorithm (ECDSA) signature
  validation in Network Security Services (NSS).

  - An error in the 'CairoTextureClientD3D9::BorrowDrawTarget' function in the
  Direct3D 9 implementation.

  - An error in 'nsZipArchive::BuildFileList' function.

  - Unspecified error in nsZipArchive.cpp script.

  - An error in the 'rx::d3d11::SetBufferData' function in the Direct3D 11
  implementation.

  - An error in the 'YCbCrImageDataDeserializer::ToDataSourceSurface' function
  in the YCbCr implementation.

  - An error in 'ArrayBufferBuilder::append' function.

  - Buffer overflow error in the 'nsXMLHttpRequest::AppendToResponseText' function.

  - An overridable error allowing for skipping pinning checks.

  - An error in PDF.js PDF file viewer.

  - An error which includes native key press information during the logging of
  crashes.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, obtain sensitive information, conduct
  man-in-the-middle attack, conduct denial-of-service attack, spoof ECDSA
  signatures and other unspecified impacts.");

  script_tag(name:"affected", value:"Mozilla Firefox before version 39.0 on
  Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 39.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-59");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-66");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-67");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-69");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-64");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-62");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-68");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(version_is_less(version:ffVer, test_version:"39.0"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "39.0"  + '\n';
  security_message(data:report);
  exit(0);
}
