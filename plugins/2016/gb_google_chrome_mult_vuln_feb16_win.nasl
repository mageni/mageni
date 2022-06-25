###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_feb16_win.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Google Chrome Multiple Vulnerabilities Feb16 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807251");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-1627", "CVE-2016-1626", "CVE-2016-1625", "CVE-2016-1623",
                "CVE-2016-1624", "CVE-2016-1622", "CVE-2016-1628");
  script_bugtraq_id(83125);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-15 12:12:26 +0530 (Mon, 15 Feb 2016)");
  script_name("Google Chrome Multiple Vulnerabilities Feb16 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - The Developer Tools subsystem does not validate URL schemes properly.

  - The 'opj_pi_update_decode_poc' function in 'pi.c' script in OpenJPEG
  miscalculates a certain layer index value.

  - The Chrome Instant feature does not ensure a New Tab Page (NTP) navigation
  target is on the most-visited or suggestions list.

  - The DOM implementation does not properly restrict frame-attach operations
  from occurring during or after frame-detach operations.

  - Integer underflow exists in the 'ProcessCommandsInternal' function in
  'dec/decode.c' script in Brotli

  - The Extensions subsystem does not prevent use of the 'Object.defineProperty'
  method to override intended extension behavior.

  - The'pi.c' script in OpenJPEG, as used in PDFium does not validate a certain
  precision value");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to bypass intended access restrictions, to execute arbitrary code or cause a
  denial of service or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"Google Chrome versions prior to
  48.0.2564.109 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  48.0.2564.109 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/02/stable-channel-update_9.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"48.0.2564.109"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"48.0.2564.109");
  security_message(data:report);
  exit(0);
}
