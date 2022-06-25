##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_900214.nasl 12623 2018-12-03 13:11:38Z cfischer $
# Description: Google Chrome multiple vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900214");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6994", "CVE-2008-6995", "CVE-2008-6996",
                "CVE-2008-6997", "CVE-2008-6998");
  script_bugtraq_id(30975, 30983, 31000, 31029, 31031, 31034, 31035, 31038);
  script_name("Google Chrome multiple vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6367");
  script_xref(name:"URL", value:"http://evilfingers.com/advisory/google_chrome_poc.php");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Sep/1020823.html");
  script_tag(name:"summary", value:"This host has Google Chrome web browser installed, which is prone
  to arbitrary code execution and Denial of Service vulnerabilities.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - the Browser failing to handle specially crafted HTML img tags, certain
    user-supplied data, HTTP view-source headers, and HTML href tags.

  - the Browser allows users to download arbitrary files without confirmation.

  - the Browser fails to perform adequate validation on user supplied data.");
  script_tag(name:"affected", value:"Google Chrome Version 0.2.149.27");
  script_tag(name:"solution", value:"Upgrade to Google Chrome 0.2.149.29 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"impact", value:"A remote user could cause Denial of Service conditions or can execute arbitrary
  code by convincing the users to visit a malicious website.");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(chromeVer != NULL)
{
  if(version_is_equal(version:chromeVer, test_version:"0.2.149.27")){
     security_message(port:0, data:"The target host was found to be vulnerable");
     exit(0);
   }
}

exit(99);
