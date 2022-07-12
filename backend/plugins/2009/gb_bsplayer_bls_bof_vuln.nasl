###############################################################################
# OpenVAS Vulnerability Test
#
# BSPlayer Stack Overflow Vulnerability BLS
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800269");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1068");
  script_bugtraq_id(34190);
  script_name("BSPlayer Stack Overflow Vulnerability BLS");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34412");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8249");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8251");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/9sg_bsplayer_seh.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_bsplayer_detect.nasl");
  script_mandatory_keys("BSPlayer/Ver");
  script_tag(name:"affected", value:"BSPlayer Version prior to 2.36.990 on Windows.");
  script_tag(name:"insight", value:"This flaw is due to boundary check error while the user supplies input data
  in the context of the application.");
  script_tag(name:"solution", value:"Upgrade to the latest version 2.36.990.");
  script_tag(name:"summary", value:"This host is running BSPlayer Free Edition and is prone to Stack
  Overflow Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft a malicious arbitrary
  'bls' file and cause stack overflow in the context of the affected
  application or can also cause remote code execution.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

playerVer = get_kb_item("BSPlayer/Ver");
if(!playerVer)
  exit(0);

if(version_is_less(version:playerVer, test_version:"2.36.990")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
