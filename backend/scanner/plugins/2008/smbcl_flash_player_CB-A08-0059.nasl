###############################################################################
# OpenVAS Vulnerability Test
# $Id: smbcl_flash_player_CB-A08-0059.nasl 12623 2018-12-03 13:11:38Z cfischer $
# Description: Adobe Flash Player 9.0.115.0 and earlier vulnerability (Windows)
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
# Modified to Implement based on 'smb_nt.inc'
#  - By Sharath S <sharaths@secpod.com> On 2009-09-14
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90019");
  script_version("$Revision: 12623 $");
  script_cve_id("CVE-2007-5275", "CVE-2007-6019", "CVE-2007-6243",
                "CVE-2007-6637", "CVE-2008-1654", "CVE-2008-1655");
  script_bugtraq_id(26930, 28694, 26966, 27034, 28696, 28697);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-09-03 22:30:27 +0200 (Wed, 03 Sep 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Flash Player 9.0.115.0 and earlier vulnerability (Windows)");

  script_tag(name:"summary", value:"The remote host is probably affected by
  the vulnerabilities described in CVE-2007-5275, CVE-2007-6019, CVE-2007-6243,
  CVE-2007-6637, CVE-2008-1654, CVE-2008-1655.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"- CVE 2007-5275
    The Adobe Macromedia Flash 9 plug-in allows remote attackers to cause a
    victim machine to establish TCP sessions with arbitrary hosts via a Flash
    (SWF) movie, related to lack of pinning of a hostname to a single IP address
    after receiving an allow-access-from element in a cross-domain-policy XML
    document, and the availability of a Flash Socket class that does not use
    the browser's DNS pins, aka DNS rebinding attacks, a different issue than
    CVE-2002-1467 and CVE-2007-4324.

  - CVE 2007-6019
    Adobe Flash Player 9.0.115.0 and earlier, and 8.0.39.0 and earlier, allows
    remote attackers to execute arbitrary code via an SWF file with a modified
    DeclareFunction2 Actionscript tag, which prevents an object from being
    instantiated properly.

  - CVE 2007-6243
    Adobe Flash Player 9.x up to 9.0.48.0, 8.x up to 8.0.35.0, and 7.x up to
    7.0.70.0 does not sufficiently restrict the interpretation and usage of
    cross-domain policy files, which makes it easier for remote attackers to
    conduct cross-domain and cross-site scripting (XSS) attacks.

  - CVE 2007-6637
    Multiple cross-site scripting (XSS) vulnerabilities in Adobe Flash Player
    allow remote attackers to inject arbitrary web script or HTML via a crafted
    SWF file, related to 'pre-generated SWF files' and Adobe Dreamweaver CS3 or
    Adobe Acrobat Connect. NOTE: the asfunction: vector is already covered by
    CVE-2007-6244.1.

  - CVE 2008-1654
    Interaction error between Adobe Flash and multiple Universal Plug and Play
    (UPnP) services allow remote attackers to perform Cross-Site Request Forgery
    (CSRF) style attacks by using the Flash navigateToURL function to send a SOAP
    message to a UPnP control point, as demonstrated by changing the primary DNS
    server.

  - CVE 2008-1655
    Unspecified vulnerability in Adobe Flash Player 9.0.115.0 and earlier, and
    8.0.39.0 and earlier, makes it easier for remote attackers to conduct DNS
    rebinding attacks via unknown vectors.");

  script_tag(name:"affected", value:"Adobe Flash Player version 9.0.115.0
  and earlier on Windows.");

  script_tag(name:"solution", value:"All Adobe Flash Player users should
  upgrade to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:playerVer, test_version:"9.0.115.0")){
  report = 'Installed version: ' + playerVer;
  security_message(data:report);
  exit(0);
}
