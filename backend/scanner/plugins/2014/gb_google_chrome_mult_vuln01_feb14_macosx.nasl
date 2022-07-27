###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_feb14_macosx.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-01 Feb2014 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804306");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-1681", "CVE-2013-6650", "CVE-2013-6649");
  script_bugtraq_id(65232, 65172, 65168);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-03 14:43:16 +0530 (Mon, 03 Feb 2014)");
  script_name("Google Chrome Multiple Vulnerabilities-01 Feb2014 (Mac OS X)");


  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A use-after-free error exists within 'RenderSVGImage::paint' function in
Blink.

  - An error related to v8 within 'StoreBuffer::ExemptPopularPages' function.

  - Many unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
service, execute an arbitrary code and other unspecified impacts.");
  script_tag(name:"affected", value:"Google Chrome version prior to 32.0.1700.102 on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to version 32.0.1700.102 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56640");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/01/stable-channel-update_27.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(version_is_less(version:chromeVer, test_version:"32.0.1700.102"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
