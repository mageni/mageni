###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_default_http_credentials_report.nasl 11663 2018-09-28 06:18:46Z cfischer $
#
# HTTP Brute Force Logins With Default Credentials Reporting
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103240");
  script_version("$Revision: 11663 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 08:18:46 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-01-06 13:47:00 +0100 (Fri, 06 Jan 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("HTTP Brute Force Logins With Default Credentials Reporting");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_END);
  script_family("Default Accounts");
  script_dependencies("default_http_auth_credentials.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("default_http_auth_credentials/started");

  script_add_preference(name:"Report timeout", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"It was possible to login into the remote Web Application using default credentials.

  As the NVT 'HTTP Brute Force Logins with default Credentials' (OID: 1.3.6.1.4.1.25623.1.0.108041) might run into a
  timeout the actual reporting of this vulnerability takes place in this NVT instead. The script preference 'Report timeout'
  allows you to configure if such an timeout is reported.");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"vuldetect", value:"Try to login with a number of known default credentials via HTTP Basic Auth.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

port = get_http_port( default:80 );

credentials = get_kb_list( "default_http_auth_credentials/" + port + "/credentials" );

if( ! isnull( credentials ) ) {

  report = 'It was possible to login with the following credentials <Url>:<User>:<Password>:<HTTP status code>\n\n';

  # Sort to not report changes on delta reports if just the order is different
  credentials = sort( credentials );

  foreach credential( credentials ) {
    url_user_pass = split( credential, sep:"#-#", keep:FALSE );
    report += report_vuln_url( port:port, url:url_user_pass[0], url_only:TRUE ) + ":" + url_user_pass[1] + '\n';
    vuln = TRUE;
  }
}

reportTimeout = script_get_preference( "Report timeout" );
if( reportTimeout == 'yes' ) {
  if( ! get_kb_item( "default_http_auth_credentials/" + port + "/no_timeout" ) ) {
    timeoutReport = "A timeout happened during the test for default logins. " +
                    "Consider raising the script_timeout value of the NVT " +
                    "'HTTP Brute Force Logins with default Credentials' " +
                    "(OID: 1.3.6.1.4.1.25623.1.0.108041).";
    log_message( port:port, data:timeoutReport);
  }
}

if( vuln ) {
  c = get_kb_item( "default_http_auth_credentials/" + port + "/too_many_logins" );
  if( c ) {
    report += '\nRemote host accept more then ' +  c + ' logins. This could indicate some error or some "broken" web application.\nScanner stops testing for default logins at this point.';
    log_message( port:port, data:report );
    exit( 0 );
  }
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
