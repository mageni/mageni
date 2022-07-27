###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rmi_insecure_default_configuration_140051.nasl 13999 2019-03-05 13:15:01Z cfischer $
#
# Java RMI Server Insecure Default Configuration Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140051");
  script_version("$Revision: 13999 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Java RMI Server Insecure Default Configuration Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=23665");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could exploit the vulnerability
  by transmitting crafted packets to the affected software. When the packets are processed,
  the attacker could execute arbitrary code on the system with elevated privileges.");

  script_tag(name:"vuldetect", value:"Check if the target tries to load a Java class via a remote HTTP URL.");

  script_tag(name:"insight", value:"The vulnerability exists because of an incorrect default configuration of the
  Remote Method Invocation (RMI) Server in the affected software.");

  script_tag(name:"solution", value:"Disable class-loading.");

  script_tag(name:"summary", value:"Multiple Java products that implement the RMI Server contain a vulnerability that
  could allow an unauthenticated, remote attacker to execute arbitrary code on a targeted system with elevated privileges.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 14:15:01 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-04 14:34:52 +0100 (Fri, 04 Nov 2016)");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_rmi_registry_detect.nasl");
  script_require_ports("Services/rmi_registry");

  exit(0);
}

include("byte_func.inc");

if( ! port = get_kb_item("Services/rmi_registry") )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

req = 'JRMI' + raw_string( 0x00,0x02,0x4b,0x00,0x00,0x00,0x00,0x00,0x00 );

send( socket:soc, data:req );
res = recv( socket:soc, length:128, min:7 );

if( hexstr( res[0] ) != '4e' || ( getword( blob:res, pos:1 ) + 7 ) != strlen( res ) )
{
  close( soc );
  exit( 0 );
}

cport = 1024 + rand() % 64512;

req = raw_string( 0x50,0xac,0xed,0x00,0x05,0x77,0x22,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,
                  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                  0x00,0xf6,0xb6,0x89,0x8d,0x8b,0xf2,0x86,0x43,0x75,0x72,0x00,0x18,0x5b,0x4c,0x6a,
                  0x61,0x76,0x61,0x2e,0x72,0x6d,0x69,0x2e,0x73,0x65,0x72,0x76,0x65,0x72,0x2e,0x4f,
                  0x62,0x6a,0x49,0x44,0x3b,0x87,0x13,0x00,0xb8,0xd0,0x2c,0x64,0x7e,0x02,0x00,0x00,
                  0x70,0x78,0x70,0x00,0x00,0x00,0x00,0x77,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                  0x00,0x73,0x72,0x00,0x14,0x4F,0x70,0x65,0x6e,0x56,0x61,0x73,0x00,0x00,0x74,0x2e,
                  0x52,0x4d,0x49,0x4c,0x6f,0x61,0x64,0x65,0x72,0xa1,0x65,0x44,0xba,0x26,0xf9,0xc2,
                  0xf4,0x02,0x00,0x00,0x74,0x00,0x33);

req += raw_string( 0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f ) + this_host() + raw_string( 0x3a ) + cport;

req += '/' + rand() + '/' + rand() + '.jar';

req += raw_string( 0x01,0x00 );

res = send_capture ( socket:soc,
                     data:req,
                     timeout:10,
                     pcap_filter: "dst host " +  this_host() + " and dst port " + cport + " and src host " +  get_host_ip() + " and tcp[tcpflags] & (tcp-syn) != 0" );

close( soc );

if( res )
{
  flags = get_tcp_element( tcp:res, element:"th_flags" );
  if( flags & TH_SYN ) # i know...filter already check for tcp-syn, but to be sure...:)
  {
    security_message( port:port );
    exit( 0 );
  }
}

close(soc);

exit( 99 );