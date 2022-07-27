###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_player_bof_vuln.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# QuickTime Player Streaming Debug Error Logging Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801427");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-1799");
  script_bugtraq_id(41962);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("QuickTime Player Streaming Debug Error Logging Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40729");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/40729");
  script_xref(name:"URL", value:"http://telussecuritylabs.com/threats/show/FSC20100727-08");
  script_xref(name:"URL", value:"http://en.community.dell.com/support-forums/virus-spyware/f/3522/t/19340212.aspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a stack-based buffer
  overflow by tricking a user into viewing a specially crafted web page that
  references a SMIL file containing an overly long URL.");
  script_tag(name:"affected", value:"QuickTime Player version prior to 7.6.7");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in 'QuickTimeStreaming.qtx' when
  constructing a string to write to a debug log file.");
  script_tag(name:"solution", value:"Upgrade to QuickTime Player version 7.6.7 or later");
  script_tag(name:"summary", value:"The host is running QuickTime Player and is prone to buffer overflow
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.apple.com/quicktime/download/");
  exit(0);
}


include("version_func.inc");

quickVer = get_kb_item("QuickTime/Win/Ver");
if(!quickVer){
  exit(0);
}

if(version_is_less(version:quickVer, test_version:"7.6.7")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
