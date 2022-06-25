###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_sec_bypass_vuln_lin.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# Adobe Flash Player Multiple Security Bypass Vulnerabilities (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800028");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-10-16 18:25:33 +0200 (Thu, 16 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6243", "CVE-2008-3873", "CVE-2007-4324",
                "CVE-2008-4401", "CVE-2008-4503");
  script_bugtraq_id(31117);
  script_name("Adobe Flash Player Multiple Security Bypass Vulnerabilities (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32163/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb08-18.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa08-08.html");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2008/10/clickjacking_security_advisory.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  script_tag(name:"impact", value:"Successful attack could allow malicious people to bypass certain
  security restrictions or manipulate certain data.");

  script_tag(name:"affected", value:"Adobe Flash Player 9.x - 9.0.124.0 on Linux.");

  script_tag(name:"insight", value:"The flaws are due to,

  - a design error in the application that allows access to the system's
    camera and microphone by tricking the user into clicking Flash Player
    access control dialogs disguised as normal graphical elements.

  - FileReference.browse() and FileReference.download() methods which can be
    called without user interaction and can potentially be used
    to trick a user into downloading or uploading files.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player 10.0.12.36.");

  script_tag(name:"summary", value:"This host has Adobe Flash Player installed and is prone to
  multiple security bypass vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

adobeVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!adobeVer){
  exit(0);
}

if(version_in_range(version:adobeVer, test_version:"9.0",
                    test_version2:"9.0.124.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
