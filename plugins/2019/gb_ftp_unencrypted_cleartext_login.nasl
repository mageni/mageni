###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ftp_unencrypted_cleartext_login.nasl 13611 2019-02-12 15:23:02Z cfischer $
#
# FTP Unencrypted Cleartext Login
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108528");
  script_version("$Revision: 13611 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:23:02 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-09 11:31:09 +0100 (Wed, 09 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_name("FTP Unencrypted Cleartext Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "gb_starttls_ftp.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/banner/available");

  script_tag(name:"summary", value:"The remote host is running a FTP service that allows cleartext logins over
  unencrypted connections.");

  script_tag(name:"impact", value:"An attacker can uncover login names and passwords by sniffing traffic to the
  FTP service.");

  script_tag(name:"vuldetect", value:"Tries to login to a non FTPS enabled FTP service without sending a
  'AUTH TLS' command first and checks if the service is accepting the login without enforcing the use of
  the 'AUTH TLS' command.");

  script_tag(name:"solution", value:"Enable FTPS or enforce the connection via the 'AUTH TLS' command. Please see
  the manual of the FTP service for more information.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );

# https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
# We can't continue if we didn't got a 2xx back for the login (e.g. got a 4/5xx)
# nb: Some FTP servers are reporting "220 (vsFTPd 3.0.3)" vs. "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------"
if( ! banner || banner !~ "^2[0-9]{2}[ -].+" )
  exit( 0 );

# FTPS
encaps = get_port_transport( port );
if( encaps > ENCAPS_IP )
  exit( 99 );

kb_creds = ftp_get_kb_creds();

# Some services handles (e.g. vsFTPD) handles Anonymous vs. Non-anonymous differently (see banner examples below).
# For both see secpod_ftp_anonymous.nasl
if( kb_creds["login"] == "anonymous" || kb_creds["login"] == "ftp" ) {
  vt_strings = get_vt_strings();
  creds[vt_strings["lowercase"]] = vt_strings["lowercase"] + "@example.com";
  creds[kb_creds["login"]] = kb_creds["pass"];
} else {
  creds["anonymous"] = "anonymous@example.com";
  creds[kb_creds["login"]] = creds["pass"];
}

auth_report  = ""; # nb: To make openvas-nasl-lint happy...
login_report = ""; # nb: To make openvas-nasl-lint happy...

# nb: Don't use exit(0); in the loop as there might be just a temporary hick-up during the scan and we want to always check both accounts...
foreach user( keys( creds ) ) {

  # nb: Don't use open_ssl_socket which would send an AUTH TLS on its own.
  soc = open_sock_tcp( port );
  if( ! soc )
    continue;

  banner = ftp_recv_line( socket:soc );

  # nb: We don't have a 3digits response, close the socket directly without sending the final "BYE" via ftp_close() below.
  if( ! banner || banner !~ "^[0-9]{3}[ -].+" ) {
    close( soc );
    continue;
  }

  # nb: Check again if something changed during the scan (e.g. account blocked, service throwing a 500, ...) after the initial grabbing of the banner via get_ftp_banner().
  if( banner !~ "^2[0-9]{2}[ -].+" ) {
    ftp_close( socket:soc );
    continue;
  }

  login = ftp_send_cmd( socket:soc, cmd:"USER " + user );

  # nb: We're vulnerable if the server is answering with something like:
  # 331 Please specify the password.
  # and not with e.g.:
  # 530 Must use AUTH TLS
  # 530 Anonymous sessions must use encryption.
  # 530 Non-anonymous sessions must use encryption.
  if( login && login =~ "^3[0-9]{2}[ -].+" ) {
    VULN = TRUE;
    if( get_kb_item( "ftp/" + port + "/starttls" ) ) {
      AUTH_TLS = TRUE;
      if( user == "anonymous" || user == "ftp" )
        auth_report  += '\n- Anonymous sessions';
      else
        auth_report  += '\n- Non-anonymous sessions';
    }

    if( user == "anonymous" || user == "ftp" )
      login_report += '\nAnonymous sessions:     ' + chomp( login );
    else
      login_report += '\nNon-anonymous sessions: ' + chomp( login );

    # nb: Send the password to finish the login process before sending the final "BYE" via ftp_close().
    ftp_send_cmd( socket:soc, cmd:"PASS " + creds["pass"] );
  }

  ftp_close( socket:soc );
}

if( VULN ) {
  report = 'The remote FTP service accepts logins without a previous sent \'AUTH TLS\' command. Response(s):\n' + login_report;
  if( AUTH_TLS )
    report += '\n\nThe remote FTP service supports the \'AUTH TLS\' command but isn\'t enforcing the use of it for:\n' + auth_report;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );