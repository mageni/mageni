# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.103955");
  script_version("2021-11-22T15:32:39+0000");
  script_tag(name:"last_modification", value:"2021-11-22 15:32:39 +0000 (Mon, 22 Nov 2021)");
  script_tag(name:"creation_date", value:"2013-11-25 12:37:04 +0700 (Mon, 25 Nov 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("SSL/TLS: Certificate Expired");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_ssl_tls_cert_details.nasl");
  script_mandatory_keys("ssl/cert/avail");

  script_tag(name:"insight", value:"This script checks expiry dates of certificates associated with
  SSL/TLS-enabled services on the target and reports whether any have already expired.");

  script_tag(name:"solution", value:"Replace the SSL/TLS certificate by a new one.");

  script_tag(name:"summary", value:"The remote server's SSL/TLS certificate has already expired.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("ssl_funcs.inc");
include("byte_func.inc");
include("list_array_func.inc");

ssls = get_kb_list( "HostDetails/SSLInfo/*" );

if( ! isnull( ssls ) ) {

  # The current time
  now = isotime_now();
  # isotime_now: "If the current time is not available an empty string is returned."
  if( strlen( now ) <= 0 )
    exit( 0 );

  # Contains the list of keys which have expired
  expired_keys = make_array();

  foreach key( keys( ssls ) ) {

    tmp   = split( key, sep:"/", keep:FALSE );
    port  = tmp[2];
    vhost = tmp[3];

    if( ! fprlist = get_kb_item( key ) )
      continue;

    result = check_cert_validity( fprlist:fprlist, port:port, vhost:vhost, check_for:"expired", now:now, timeframe:0 );
    if( result )
      expired_keys[port] = result;
  }

  foreach port( keys( expired_keys ) ) {
    report = "The certificate of the remote service expired on ";
    report += isotime_print( get_kb_item( expired_keys[port] + "notAfter" ) ) + '.\n';
    report += cert_summary( key:expired_keys[port] );
    security_message( data:report, port:port );
  }
  exit( 0 );
}

exit( 99 );