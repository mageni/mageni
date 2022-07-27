###############################################################################
# OpenVAS Vulnerability Test
# $Id: wu_ftpd_glob2.nasl 13610 2019-02-12 15:17:00Z cfischer $
#
# FTPD glob (too many *) Denial of Service
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

# References:
# http://www.idefense.com/application/poi/display?id=207&type=vulnerabilities

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17602");
  script_version("$Revision: 13610 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:17:00 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-0256");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FTPD glob (too many *) denial of service");
  script_category(ACT_MIXED_ATTACK);
  script_family("FTP");
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_dependencies("gb_wu-ftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("wu-ftpd/installed");

  script_tag(name:"summary", value:"WU-FTPD is prone to a Denial of Service vulnerability.");

  script_tag(name:"insight", value:"WU-FTPD exhausts all available resources on the server
  when it receives the following request several times:

  LIST *****[...]*.*");

  script_tag(name:"solution", value:"Contact your vendor for a fix.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit( 0 );
vers = infos['version'];
path = infos['location']; # To have a reference to the Detection-NVT

if( safe_checks() ) {
  if( egrep( string:vers, pattern:"^2\.6\.(1|2|2\(1\))" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

for( i = 0; i < 2; i ++ ) {

  soc = open_sock_tcp( port );
  if( ! soc || ! ftp_authenticate( socket:soc, user:user, pass:pass ) ) exit( 0 );

  pasv = ftp_pasv( socket:soc );
  soc2 = open_sock_tcp( pasv );
  # Above 194 *, the server answers "sorry input line too long"
  if( i ) {
    send( socket:soc, data:'LIST ***********************************************************************************************************************************************************************************************.*\r\n' );
  } else {
    send( socket:soc, data:'LIST *.*\r\n' );
  }

  t1 = unixtime();
  b  = ftp_recv_line( socket:soc );

  repeat
    data = recv( socket:soc2, length:1024 );
  until( ! data );

  t[i] = unixtime() - t1;
  #b = ftp_recv_line( socket:soc );
  close( soc );
  soc = NULL;
  close( soc2 );
}

if( t[0] == 0 )
  t[0] = 1;

if( t[1] > 3 * t[0] ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );