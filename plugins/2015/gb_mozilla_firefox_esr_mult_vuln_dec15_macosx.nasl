###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_mult_vuln_dec15_macosx.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Mozilla Firefox ESR Multiple Vulnerabilities - Dec15 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807007");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-7201", "CVE-2015-7205", "CVE-2015-7210", "CVE-2015-7212",
                "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7222");
  script_bugtraq_id(79279, 79283);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-18 11:44:05 +0530 (Fri, 18 Dec 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities - Dec15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are exists due to,

  - Multiple unspecified vulnerabilities in the browser engine.

  - Integer underflow in the 'RTPReceiverVideo::ParseRtpPacket' function.

  - Use-after-free error in WebRTC that occurs due to timing issues in WebRTC
    when closing channels.

  - Integer overflow in the 'mozilla::layers::BufferTextureClient::AllocateForSurface'
    function.

  - Integer overflow in the 'MPEG4Extractor::readMetaData' function in
    'MPEG4Extractor.cpp' script in libstagefright.

  - Cross-site reading vulnerability through data and view-source URIs.

  - Integer underflow in the 'Metadata::setData' function in 'MetaData.cpp' in
    libstagefright.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service, bypass security restrictions,
  obtain sensitive information, execute arbitrary code and some unspecified
  impacts.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version 38.x
  before 38.5 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version
  38.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-134");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-138");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(ffVer =~ "^38\.")
{
  if(version_is_less(version:ffVer, test_version:"38.5"))
  {
    report = 'Installed version: ' + ffVer + '\n' +
             'Fixed version:     ' + "38.5" + '\n';
    security_message(data:report);
    exit(0);
  }
}
