###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sea_monkey_mult_vuln01_jan15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# SeaMonkey Multiple Vulnerabilities-01 Jan15 (Windows)
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

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805254");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-8642", "CVE-2014-8641", "CVE-2014-8640", "CVE-2014-8639",
                "CVE-2014-8638", "CVE-2014-8637", "CVE-2014-8636", "CVE-2014-8635",
                "CVE-2014-8634");
  script_bugtraq_id(72042, 72044, 72045, 72046, 72047, 72048, 72041, 72050, 72049);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-20 14:51:45 +0530 (Tue, 20 Jan 2015)");
  script_name("SeaMonkey Multiple Vulnerabilities-01 Jan15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with SeaMonkey and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Some unspecified errors.

  - An error when rendering a bitmap image by the bitmap decoder within a
  canvas element.

  - An error when handling a request from 'navigator.sendBeacon' API interface
  function.

  - An error when handling a '407 Proxy Authentication' response with a
  'Set-Cookie' header from a web proxy.

  - A use-after-free error when handling tracks within WebRTC.

  - An error when handling the 'id-pkix-ocsp-nocheck' extension during
  verification of a delegated OCSP (Online Certificate Status Protocol) response
  signing certificate.

  - An error when handling DOM (Document Object Model) objects with certain
  properties.

  - Improper restriction of timeline operations by the
  'mozilla::dom::AudioParamTimeline::AudioNodeInputValue' function in the Web
  Audio API.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose potentially sensitive information, bypass certain security
  restrictions, and compromise a user's system.");

  script_tag(name:"affected", value:"SeaMonkey version before 2.32 on Windows.");

  script_tag(name:"solution", value:"Upgrade to SeaMonkey version 2.32 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62253");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-01");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-03");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-04");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-02");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-05");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-09");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-08");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-06");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/seamonkey");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:smVer, test_version:"2.32"))
{
  fix = "2.32";
  report = 'Installed version: ' + smVer + '\n' +
             'Fixed version:     ' + fix  + '\n';
  security_message(data:report );
  exit(0);
}
