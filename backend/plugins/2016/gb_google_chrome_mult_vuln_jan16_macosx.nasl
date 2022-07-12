###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_jan16_macosx.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Google Chrome Multiple Vulnerabilities Jan16 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806930");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2015-8664", "CVE-2015-6792");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-05 13:05:38 +0530 (Tue, 05 Jan 2016)");
  script_name("Google Chrome Multiple Vulnerabilities Jan16 (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An Integer overflow in the 'WebCursor::Deserialize' function in
    'content/common/cursors/webcursor.cc' script

  - An error in the MIDI subsystem does not properly handle the
    sending of data.");

  script_tag(name:"impact", value:"Successful exploitation would allow a attacker
  to execute arbitrary code or cause a denial of service or possibly have unspecified
  other impact.");

  script_tag(name:"affected", value:"Google Chrome versions prior to 47.0.2526.106
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  47.0.2526.106 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/12/stable-channel-update_15.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"47.0.2526.106"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
           'Fixed version:     47.0.2526.106'  + '\n';
  security_message(data:report);
  exit(0);
}
