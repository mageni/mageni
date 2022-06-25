###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_jul13_win.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-01 July13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803902");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2013-2880", "CVE-2013-2879", "CVE-2013-2878", "CVE-2013-2877",
                "CVE-2013-2876", "CVE-2013-2875", "CVE-2013-2874", "CVE-2013-2873",
                "CVE-2013-2872", "CVE-2013-2871", "CVE-2013-2870", "CVE-2013-2869",
                "CVE-2013-2868", "CVE-2013-2867", "CVE-2013-2853");
  script_bugtraq_id(61046, 61052, 61055, 61047, 61059, 61061, 61057, 61051, 61056,
                    61060, 61053, 61054, 61058, 61050, 61049);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-07-16 18:40:12 +0530 (Tue, 16 Jul 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 July13 (Windows)");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
bypass security restrictions, disclose potentially sensitive data, or cause
denial of service condition.");
  script_tag(name:"affected", value:"Google Chrome version prior to 28.0.1500.71 on Windows.");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Error exists when setting up sign-in and sync operations.

  - An out-of-bounds read error exists within text handling.

  - 'parser.c in libxml2' has out-of-bounds read error, related to the lack of
   checks for the XML_PARSER_EOF state.

  - 'browser/extensions/api/tabs/tabs_api.cc' does not enforce restrictions on
   the capture of screenshots by extensions.

  - An out-of-bounds read error exists in SVG handling.

  - Unspecified error related to GL textures, only when an Nvidia GPU is used.

  - Unspecified use-after-free vulnerabilities.

  - An out-of-bounds read error exists within JPEG2000 handling.

  - Unspecified error exists within sync of NPAPI extension component.

  - Does not properly prevent pop.

  - HTTPS implementation does not ensure how headers are terminated.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 28.0.1500.71 or later.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54017");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/07/stable-channel-update.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"28.0.1500.71"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
