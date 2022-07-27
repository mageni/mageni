###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln_dec15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Mozilla Firefox Multiple Vulnerabilities - Dec15 (Windows)
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807004");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-7201", "CVE-2015-7202", "CVE-2015-7203", "CVE-2015-7204",
                "CVE-2015-7205", "CVE-2015-7207", "CVE-2015-7208", "CVE-2015-7210",
                "CVE-2015-7211", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214",
                "CVE-2015-7215", "CVE-2015-7218", "CVE-2015-7219", "CVE-2015-7220",
                "CVE-2015-7221", "CVE-2015-7222", "CVE-2015-7223");
  script_bugtraq_id(79283, 79279, 79280);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-12-18 10:31:01 +0530 (Fri, 18 Dec 2015)");
  script_name("Mozilla Firefox Multiple Vulnerabilities - Dec15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple unspecified vulnerabilities in the browser engine.

  - Buffer overflow in the 'DirectWriteFontInfo::LoadFontFamilyData' function in
    'gfx/thebes/gfxDWriteFontList.cpp' script.

  - An implementation error with unboxed objects and property storing in the
    JavaScript engine.

  - Integer underflow in the 'RTPReceiverVideo::ParseRtpPacket' function.

  - Improper restriction of the availability of IFRAME Resource Timing API times.

  - Control characters are allowed to set in cookies.

  - Use-after-free error in WebRTC that occurs due to timing issues in WebRTC
    when closing channels.

  - Mishandling of the '#' (number sign) character while 'data: URI' parsing.

  - Integer overflow in the 'mozilla::layers::BufferTextureClient::AllocateForSurface'
    function.

  - Integer overflow in the 'MPEG4Extractor::readMetaData' function in
    'MPEG4Extractor.cpp' script in libstagefright.

  - Cross-site reading vulnerability through data and view-source URIs.

  - Cross-origin information leak through the error events in web workers.

  - Multiple errors in 'HTTP/2' implementation.

  - Buffer overflow in the 'XDRBuffer::grow' function in 'js/src/vm/Xdr.cpp'
    script.

  - Buffer overflow in the 'nsDeque::GrowCapacity' function in
    'xpcom/glue/nsDeque.cpp' script.

  - Integer underflow in the 'Metadata::setData' function in 'MetaData.cpp' in
    libstagefright

  - Error in WebExtension APIs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service, bypass security restrictions,
  obtain sensitive information, execute arbitrary script code, spoof web sites
  and some unspecified impacts.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 43.0 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 43.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-149");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-138");

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
if(version_is_less(version:ffVer, test_version:"43.0"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "43.0" + '\n';
  security_message(data:report);
  exit(0);
}
