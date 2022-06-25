###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_dec10_win01.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Google Chrome multiple vulnerabilities - Dec10 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801678");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_bugtraq_id(45170);
  script_cve_id("CVE-2010-4482", "CVE-2010-4483", "CVE-2010-4484",
                "CVE-2010-4485", "CVE-2010-4486", "CVE-2010-4488",
                "CVE-2010-4489", "CVE-2010-4490", "CVE-2010-4491",
                "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4494");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - Dec10 (Windows)");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/12/stable-beta-channel-updates.html");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 8.0.552.215 on windows");
  script_tag(name:"insight", value:"The multiple flaws are due to,

  - Possible pop-up blocker bypass via unknown vectors.

  - Cross-origin video theft with canvas elements allows remote attackers to
    bypass the Same Origin Policy and obtain potentially sensitive video data.

  - Improper handling of HTML5 databases allows attackers to cause a denial of
    service.

  - Excessive file dialogs could lead to a browser crash.

  - Use after free error in history handling.

  - Browser crash with HTTP proxy authentication.

  - Out-of-bounds read regression in WebM video support.

  - Crash due to bad indexing with malformed video.

  - Possible browser memory corruption via malicious privileged extension.

  - Use after free error with SVG animations.

  - Use after free error in mouse dragging event handling.

  - A double free error in XPath handling.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 8.0.552.215 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The host is running Google Chrome and is prone to multiple
  vulnerabilities.");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"8.0.552.215")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
