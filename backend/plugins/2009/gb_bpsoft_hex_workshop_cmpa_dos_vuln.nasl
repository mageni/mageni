###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bpsoft_hex_workshop_cmpa_dos_vuln.nasl 14335 2019-03-19 14:46:57Z asteins $
#
# BreakPoint Software Hex Workshop Denial of Service vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800327");
  script_version("$Revision: 14335 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5756");
  script_bugtraq_id(33023);
  script_name("BreakPoint Software Hex Workshop Denial of Service vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/Advisories/33327");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7592");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_bpsoft_hex_workshop_detect.nasl");
  script_mandatory_keys("BPSoft/HexWorkshop/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code and
  can cause Denial of Service to the application.");
  script_tag(name:"affected", value:"BreakPoint Software Hex Workshop version 5.1.4 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is due to improper boundary checks in Color Mapping or
  .cmap file via a long mapping reference.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to BreakPoint Software Hex Workshop version 6.0.1 or later.");
  script_tag(name:"summary", value:"This host has Hex Workshop installed and is prone to Denial of
  Service vulnerability.");

  script_xref(name:"URL", value:"http://www.bpsoft.com/downloads");
  exit(0);
}

include("version_func.inc");

hwVer = get_kb_item("BPSoft/HexWorkshop/Ver");
if(!hwVer){
  exit(0);
}

if(version_in_range(version:hwVer, test_version:"1.0",
                                   test_version2:"5.1.4.4188")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
