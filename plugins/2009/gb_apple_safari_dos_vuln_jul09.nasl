###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_dos_vuln_jul09.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# Apple Safari Denial Of Service Vulnerability - Jul09
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800656");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-07-12 15:16:55 +0200 (Sun, 12 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_cve_id("CVE-2009-2420", "CVE-2009-2421");
  script_name("Apple Safari Denial Of Service Vulnerability - Jul09");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/504479");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"affected", value:"Apple Safari 3.2.3 on Windows.");
  script_tag(name:"insight", value:"The flaws are due to

  - Error in 'CFCharacterSetInitInlineBuffer' method in CoreFoundation.dll
   when processing high-bit character in a URL fragment for an unspecified
   protocol.

  - Error in implementing the file 'protocol handler' when processing vectors
   involving an unspecified HTML tag.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is installed with Apple Safari web browser and is prone
to Denial of Service vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation allow attackers to execute arbitrary
code or can even crash the browser.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

if(version_is_equal(version:safVer, test_version:"3.525.29.0")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}
