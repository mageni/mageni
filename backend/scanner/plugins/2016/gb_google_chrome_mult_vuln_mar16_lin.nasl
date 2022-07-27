###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_mar16_lin.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Google Chrome Multiple Vulnerabilities Mar16 (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807458");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-2845", "CVE-2016-2844", "CVE-2016-2843", "CVE-2016-1642",
                "CVE-2016-1641", "CVE-2016-1640", "CVE-2016-1639", "CVE-2016-1637",
                "CVE-2016-1638", "CVE-2016-1636", "CVE-2016-1635", "CVE-2016-1634",
                "CVE-2016-1633", "CVE-2016-1632", "CVE-2016-1631", "CVE-2016-1630");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-08 12:06:31 +0530 (Tue, 08 Mar 2016)");
  script_name("Google Chrome Multiple Vulnerabilities Mar16 (Linux)");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - The Content Security Policy (CSP) implementation in Blink does not ignore
    a URL's path component in the case of a ServiceWorker fetch.

  - 'WebKit/Source/core/layout/LayoutBlock.cpp' script in Blink does not
    properly determine when anonymous block wrappers may exist.

  - Multiple unspecified vulnerabilities.

  - Use-after-free vulnerabilities.

  - The Web Store inline-installer implementation in the Extensions UI does not
    block installations upon deletion of an installation frame.

  - The 'SkATan2_255' function in 'effects/gradients/SkSweepGradient.cpp' script
    in Skia mishandles arctangent calculations.

  - Extensions subsystem does not properly validate the functions.

  - The 'PendingScript::notifyFinished' function in 'WebKit/Source/core/dom/PendingScript.cpp'
    script relies on memory-cache information about integrity-check
    occurrences instead of integrity-check successe.

  - 'extensions/renderer/render_frame_observer_natives.cc' script does not properly
    consider object lifetimes and re-entrancy issues during
    OnDocumentElementCreated handling.

  - The 'PPB_Flash_MessageLoop_Impl::InternalRun' function in 'content/renderer/pepper/ppb_flash_message_loop_impl.cc'
    script in the Pepper plugin mishandles nested message loops.

  - The 'ContainerNode::parserRemoveChild' function in 'WebKit/Source/core/dom/ContainerNode.cpp'
    script in Blink mishandles widget updates.");

  script_tag(name:"impact", value:"Successful exploitation would allow remote
  attacker to obtain sensitive information, to cause a denial of service, to bypass
  intended access restrictions, to bypass the Subresource Integrity (aka SRI)
  protection mechanism and to bypass the Same Origin Policy.");

  script_tag(name:"affected", value:"Google Chrome versions prior to
  49.0.2623.75 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  49.0.2623.75 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/03/stable-channel-update.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"49.0.2623.75"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"49.0.2623.75");
  security_message(data:report);
  exit(0);
}
