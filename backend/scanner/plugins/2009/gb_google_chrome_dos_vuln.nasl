###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_dos_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Google Chrome Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800566");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1514");
  script_bugtraq_id(34786);
  script_name("Google Chrome Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8573");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/378891.php");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"affected", value:"Google Chrome version 1.0.154.53 and prior.");
  script_tag(name:"insight", value:"NULL-pointer deference in browser which causes application crash
through a throw statement with a long exception value.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to Denial
of Service vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft a malicious
html file and trick the user to open the malicious file which leads to denial
of service on the affected system.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(chromeVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"1.0.154.53")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
