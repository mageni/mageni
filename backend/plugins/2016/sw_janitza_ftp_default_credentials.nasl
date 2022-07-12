###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_janitza_ftp_default_credentials.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# Janitza Multiple Devices FTP Default Credentials
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2016 SCHUTZWERK GmbH, https://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111104");
  script_version("$Revision: 13499 $");
  script_cve_id("CVE-2015-3968");
  script_bugtraq_id(77291);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Janitza Multiple Devices FTP Default Credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-06-11 11:12:12 +0200 (Sat, 11 Jun 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ready_banner/detected");

  script_xref(name:"URL", value:"https://wiki.janitza.de/display/GRIDVIS40/UMG+604+-+Passwort");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77291");

  script_tag(name:"summary", value:'The remote Janitza device has default credentials set.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.');

  script_tag(name:"vuldetect", value:'Connect to the FTP service and try to login with default credentials.');

  script_tag(name:"insight", value:'It was possible to login with default credentials:"admin:Janitza", "user:Janitza" or "guest:Janitza".');

  script_tag(name:"solution", value:'Change the default username and password.');

  script_tag(name:"affected", value:'Janitza UMG 508, 509, 511, 604, and 605 devices.');

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("ftp_func.inc");

report = 'It was possible to login using the following default credentials:\n';

creds = make_array( "admin", "Janitza",
                    "user", "Janitza",
                    "guest", "Janitza" );

port = get_ftp_port( default:21 );

if( get_kb_item( "ftp/" + port + "/anonymous" ) ) exit( 0 );

if( "220 Ready" >!< get_ftp_banner( port:port ) ) exit( 0 );

foreach cred ( keys( creds ) ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  if( ftp_authenticate( socket:soc, user:cred, pass:creds[cred] ) ) {
    report += '\n' + cred + ":" + creds[cred];
    VULN = TRUE;
  }
  ftp_close( socket:soc );
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );