###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_xml_dos_vuln_win_apr09.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Apple Safari Denial of Service Vulnerability (Windows) - Apr09
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
  script_oid("1.3.6.1.4.1.25623.1.0.800549");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-04-07 07:29:53 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1233");
  script_bugtraq_id(34318);
  script_name("Apple Safari Denial of Service Vulnerability (Windows) - Apr09");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8325");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49527");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Attacker could exploit this vulnerability to cause the browser to crash.");
  script_tag(name:"affected", value:"Apple Safari version 4 beta and prior on Windows.");
  script_tag(name:"insight", value:"Improper parsing of XML documents while persuading a victim to open a
  specially-crafted XML document containing an overly large number of nested
  elements crashes the Browser.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Apple Safari Web Browser and is prone
  to denial of service vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer){
  exit(0);
}

# Apple Safari Version <= (4.28.16.0) 4 build 528.16
if(version_is_less_equal(version:safariVer, test_version:"4.28.16.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
