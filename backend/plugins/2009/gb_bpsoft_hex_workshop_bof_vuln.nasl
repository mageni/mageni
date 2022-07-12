###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bpsoft_hex_workshop_bof_vuln.nasl 11554 2018-09-22 15:11:42Z cfischer $
#
# BreakPoint Software, Hex Workshop Buffer Overflow vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.800528");
  script_version("$Revision: 11554 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-03-10 11:59:23 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0812");
  script_bugtraq_id(33932);
  script_name("BreakPoint Software, Hex Workshop Buffer Overflow vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34021");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8121");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_bpsoft_hex_workshop_detect.nasl");
  script_mandatory_keys("BPSoft/HexWorkshop/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attacker to execute arbitrary
  code and can cause denial-of-service.");
  script_tag(name:"affected", value:"BreakPoint Software, Hex Workshop version 6.0.1.4603 and prior on Windows.");
  script_tag(name:"insight", value:"Application fails to adequately sanitize user input data, which in turn
  leads to boundary error while processing of Intel .hex files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host has Hex Workshop installed and is prone to Stack
  based Buffer Overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

hwVer = get_kb_item("BPSoft/HexWorkshop/Ver");
if(!hwVer){
  exit(0);
}

if(version_is_less_equal(version:hwVer, test_version:"6.0.1.4603")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
