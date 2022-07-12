###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_cmd_exec_vuln.nasl 12623 2018-12-03 13:11:38Z cfischer $
#
# Google Chrome Argument Injection Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900419");
  script_version("$Revision: 12623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 14:11:38 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5749");
  script_bugtraq_id(32997);
  script_name("Google Chrome Argument Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7566");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/499581/100/0/threaded");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code
  in the context of the web browser and can compromise the remote system
  by executing mailcious commands.");
  script_tag(name:"affected", value:"Google Chrome version 1.0.154.36 and prior on Windows");
  script_tag(name:"insight", value:"The flaw is due to lack of sanitization check of user supplied input via

  - -renderer-path option in a chromehtml: URI.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 4.1.249.1064 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host has installed Google Chrome and is prone to argument
  injection vulnerability.");

  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"1.0.154.36")){
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
