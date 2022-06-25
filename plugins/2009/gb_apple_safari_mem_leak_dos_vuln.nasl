###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mem_leak_dos_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Apple Safari WebKit Property Memory Leak Remote DoS Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800100");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-01-13 15:40:34 +0100 (Tue, 13 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5821");
  script_bugtraq_id(33080);
  script_name("Apple Safari WebKit Property Memory Leak Remote DoS Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0812-exploits/safari_webkit_ml.txt");
  script_xref(name:"URL", value:"http://jbrownsec.blogspot.com/2008/12/new-year-research-are-upon-us.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"affected", value:"Apple Safari 3.2 and prior on Windows (Any).");
  script_tag(name:"insight", value:"The flaw is due to WebKit library which fails to validate the user
  input via a long ALINK attribute in a BODY element in an HTML document.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with Apple Safari web browser and is prone
  to denial of service.");
  script_tag(name:"impact", value:"Successful exploitation allow attackers to execute arbitrary code
  or can even crash the browser.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

if(version_is_less_equal(version:safVer, test_version:"3.525.26.13")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
