###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_jan14_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-01 Jan2014 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804186");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-6641", "CVE-2013-6643", "CVE-2013-6644", "CVE-2013-6645",
                "CVE-2013-6646");
  script_bugtraq_id(64805, 64981);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-21 12:19:43 +0530 (Tue, 21 Jan 2014)");
  script_name("Google Chrome Multiple Vulnerabilities-01 Jan2014 (Windows)");


  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A use-after-free error exists within web workers.

  - Use-after-free vulnerability in 'FormAssociatedElement::formRemovedFromTree'
 function in Blink.

  - Multiple unspecified errors.

  - Use-after-free vulnerability in 'OnWindowRemovingFromRootWindow' function.

  - An error in 'OneClickSigninBubbleView::WindowClosing' function.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct  denial of
service, execute an arbitrary code, trigger a sync with an arbitrary Google
account and other impacts.");
  script_tag(name:"affected", value:"Google Chrome version prior to 32.0.1700.76 on Windows.");
  script_tag(name:"solution", value:"Upgrade to version 32.0.1700.76 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56248");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1029611");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/01/stable-channel-update.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(version_is_less(version:chromeVer, test_version:"32.0.1700.76"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
