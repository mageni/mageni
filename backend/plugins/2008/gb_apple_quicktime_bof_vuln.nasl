###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Apple QuickTime Malformed .mov File Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800319");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-12-18 14:07:48 +0100 (Thu, 18 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5406");
  script_bugtraq_id(32540);
  script_name("Apple QuickTime Malformed .mov File Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7296");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46984");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl",
                      "secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attacker execution of arbitrary codes
  in the context of the affected application and can perform denial of service.");
  script_tag(name:"affected", value:"Apple QuickTime version 7.5.5 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to a failure in handling long arguments on a .mov file.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Apple QuickTime version 7.6.6 or later.");
  script_tag(name:"summary", value:"This host has QuickTime installed, which is prone to Buffer Overflow
  Vulnerability.");
  script_xref(name:"URL", value:"http://www.apple.com/");
  exit(0);
}

if( ! version = get_kb_item( "QuickTime/Win/Ver" ) ) exit( 0 );

if( version =~ "^7\.5\.5$" ) {
  security_message( port:0 );
  exit( 0 );
}

exit( 99 );