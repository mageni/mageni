###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssl_cert_in_chain_soonexpired.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# SSL/TLS: Certificate In Chain Will Soon Expire
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
# of the License, or (at your option) any later version
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

# How many days in advance to warn of certificate expiry.
lookahead = 60;

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105891");
  script_version("$Revision: 14181 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-16 11:11:32 +0200 (Fri, 16 Sep 2016)");
  script_name("SSL/TLS: Certificate In Chain Will Soon Expire");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssl_cert_chain_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"insight", value:"This script checks expiry dates of certificates in the chain associated with
  SSL/TLS-enabled services on the target and reports whether any will expire during
  then next " + lookahead + " days.");

  script_tag(name:"solution", value:"Prepare to replace the SSL/TLS certificate by a new one.");

  script_tag(name:"summary", value:"A certificate in the chain of the remote server will soon expire.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("byte_func.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

function check_validity( port, now ) {

  if ( ! port )
    return;

  expired = make_list();

  if( ! c = get_kb_list( "cert_chain/" + port + "/chain") ) exit( 0 );

  foreach f ( c ) {

    f = base64_decode( str:f );

    if( ! certobj = cert_open( f ) )
      continue;

    expire_date = cert_query( certobj, "not-after" );

    if( expire_date < now ) {
      subject = cert_query( certobj, "subject" );
      expired = make_list( expired, subject + '>##<' + expire_date );
    }
  }

  if( max_index( expired ) > 0 )
    return expired;

  return;
}

if( ! port = get_ssl_port() )
  exit(0);

now = isotime_now();
if( strlen( now ) <= 0 ) exit( 0 ); # isotime_now: "If the current time is not available an empty string is returned."
future = isotime_add( now, days:lookahead );
if( isnull( future ) ) exit( 0 ); # isotime_add: "or NULL if the provided ISO time string is not valid or the result would overflow (i.e. year > 9999).

if( ret = check_validity( port: port, now:future ) ) {
  foreach a ( ret ) {
    exp = split( a, sep: ">##<", keep: FALSE );

    subj = exp[0];
    exp_date = exp[1];

    report_expired += 'Subject:     ' + subj + '\nExpired on:  ' + isotime_print(exp_date) + '\n\n';
  }

  report = 'The following certificate(s) in the chain of the remote service will expire soon.\n\n' +
           report_expired;
  log_message(port: port, data: report);
  exit(0);
}

exit(0);