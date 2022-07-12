###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_aug12_lin.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - August 12 (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802930");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-2847", "CVE-2012-2860", "CVE-2012-2858", "CVE-2012-2857",
                "CVE-2012-2856", "CVE-2012-2855", "CVE-2012-2854", "CVE-2012-2853",
                "CVE-2012-2852", "CVE-2012-2851", "CVE-2012-2850", "CVE-2012-2849",
                "CVE-2012-2848", "CVE-2012-2846", "CVE-2012-2859");
  script_bugtraq_id(54749);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-09 12:33:02 +0530 (Thu, 09 Aug 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - August 12 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50105/");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/07/stable-channel-release.html");

  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 21.0.1180.57 on Linux");
  script_tag(name:"insight", value:"The flaws are due to

  - The application does not properly re-prompt the user when downloading
    multiple files and can be exploited to trick the user into downloading a
    malicious file.

  - An error when handling drag and drop events.

  - Integer overflow errors, use-after-free error, out-of-bounds write error
    exists within the PDF viewer.

  - A use-after-free error exists when handling object linkage in PDFs.

  - An error within the 'webRequest' module can be exploited to cause
    interference with the Chrome Web Store.

  - A use-after-free error exits when handling CSS DOM objects.

  - An error within the WebP decoder can be exploited to cause a buffer
    overflow.

  - An out-of-bounds access error exists when clicking in date picker.

  - An error when handling renderer processes can be exploited to bypass the
    cross-process policy.

  - An unspecified error exists within tab handling.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 21.0.1180.57 or later.");
  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"21.0.1180.57")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
