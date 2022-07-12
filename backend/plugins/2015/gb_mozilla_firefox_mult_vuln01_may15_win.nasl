###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln01_may15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Mozilla Firefox Multiple Vulnerabilities-01 May15 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805625");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-2708", "CVE-2015-2709", "CVE-2015-2710", "CVE-2015-2711",
                "CVE-2015-2712", "CVE-2015-2713", "CVE-2015-2715", "CVE-2015-2716",
                "CVE-2015-2717", "CVE-2015-2718", "CVE-2015-2720", "CVE-2015-0797",
                "CVE-2011-3079", "CVE-2015-4496");
  script_bugtraq_id(74615, 74611, 53309, 76333);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-21 18:29:20 +0530 (Thu, 21 May 2015)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-01 May15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The update implementation does not ensure that the pathname for updater.exe
    corresponds to the application directory.

  - Flaw in WebChannel.jsm module in Mozilla Firefox.

  - Integer overflow in libstagefright in Mozilla Firefox.

  - Buffer overflow in the XML parser in Mozilla Firefox.

  - Race condition in the 'nsThreadManager::RegisterCurrentThread' function in
    Mozilla Firefox.

  - Use-after-free vulnerability in the SetBreaks function in Mozilla Firefox.

  - Flaw in Mozilla Firefox so that does not recognize a referrer policy
    delivered by a referrer META element.

  - Heap-based buffer overflow in the SVGTextFrame class in Mozilla Firefox.

  - Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox.

  - Flaw in asm.js implementation in Mozilla Firefox.

  - Flaw in GStreamer in Mozilla Firefox.

  - Flaw in Inter-process Communication (IPC) implementation.

  - Multiple integer overflows in libstagefright in Mozilla Firefox.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially execute arbitrary
  code, bypass security restrictions, bypass origin restrictions, gain
  knowledge of sensitive information, run custom code, cause the server to
  crash and gain privileged access.");

  script_tag(name:"affected", value:"Mozilla Firefox before version 38.0 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 38.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-46");

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

if(version_is_less(version:ffVer, test_version:"38.0"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "38.0"  + '\n';
  security_message(data:report);
  exit(0);
}
