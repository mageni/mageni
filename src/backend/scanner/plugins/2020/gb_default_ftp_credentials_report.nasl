# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108718");
  script_version("2020-03-06T10:08:54+0000");
  script_tag(name:"last_modification", value:"2020-03-10 11:03:30 +0000 (Tue, 10 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-05 14:02:28 +0000 (Thu, 05 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FTP Brute Force Logins Reporting");
  script_category(ACT_END);
  script_family("Brute force attacks");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gb_default_ftp_credentials.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("default_ftp_credentials/started");

  script_add_preference(name:"Report timeout", type:"checkbox", value:"no", id:1);

  script_tag(name:"summary", value:"It was possible to login into the remote FTP server using weak/known credentials.

  As the VT 'FTP Brute Force Logins' (OID: 1.3.6.1.4.1.25623.1.0.108717) might run into a timeout the actual
  reporting of this vulnerability takes place in this VT instead. The script preference 'Report timeout'
  allows you to configure if such an timeout is reported.");

  script_tag(name:"vuldetect", value:"Reports weak/known credentials detected by the VT 'FTP Brute Force Logins'
  (OID: 1.3.6.1.4.1.25623.1.0.108717).");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");

port = get_ftp_port( default:21 );

credentials = get_kb_list( "default_ftp_credentials/" + port + "/credentials" );

if( ! isnull( credentials ) ) {

  report = 'It was possible to login with the following credentials <User>:<Password>\n\n';

  # Sort to not report changes on delta reports if just the order is different
  credentials = sort( credentials );

  foreach credential( credentials ) {
    report += credential + '\n';
    vuln = TRUE;
  }
}

reportTimeout = script_get_preference( "Report timeout", id:1 );
if( reportTimeout == "yes" ) {
  if( ! get_kb_item( "default_ftp_credentials/" + port + "/no_timeout" ) ) {
    timeoutReport = "A timeout happened during the test for default logins. " +
                    "Consider raising the script_timeout value of the VT " +
                    "'FTP Brute Force Logins' (OID: 1.3.6.1.4.1.25623.1.0.108717).";
    log_message( port:port, data:timeoutReport );
  }
}

if( vuln ) {
  c = get_kb_item( "default_ftp_credentials/" + port + "/too_many_logins" );
  if( c ) {
    report += '\nRemote host accept more than ' + c + ' logins. This could indicate some error or some "broken" device.\nScanner stops testing for default logins at this point.';
  }
  security_message( port:port, data:chomp( report ) );
  exit( 0 );
}

exit( 99 );
