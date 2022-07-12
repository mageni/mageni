###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_untrusted_ca_detect.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# SSL/TLS: Untrusted Certificate Authorities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113054");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-21 10:13:14 +0100 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("SSL/TLS: Untrusted Certificate Authorities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("ssl_cert_details.nasl");
  script_mandatory_keys("ssl/cert/avail");

  script_tag(name:"summary", value:"The service is using a SSL/TLS certificate from a known untrusted certificate authority.
  An attacker could use this for MitM attacks, accessing sensible data and other attacks.");

  script_tag(name:"vuldetect", value:"The script reads the certificate used by the target host and checks if it was
  signed by an untrusted certificate authority.");

  script_tag(name:"solution", value:"Replace the SSL/TLS certificate with one signed by a trusted certificate authority.");

  exit(0);
}


include("ssl_funcs.inc");

ssls = get_kb_list( "HostDetails/SSLInfo/*" );

if( ! isnull( ssls ) ) {

  # Contains the list of keys which are signed by an untrusted CA
  untrusted_keys = make_array();

  foreach key( keys( ssls ) ) {

    tmp   = split( key, sep:"/", keep:FALSE );
    port  = tmp[2];
    vhost = tmp[3];

    fprlist = get_kb_item( key );
    if( ! fprlist ) continue;

    result = check_cert_validity( fprlist:fprlist, port:port, vhost:vhost, check_for:"untrusted_ca" );
    if( result ) {
      untrusted_keys[port] = result;
    }
  }

  foreach port( keys( untrusted_keys ) ) {
    info   = untrusted_keys[port];
    issuer = info[0];
    key    = info[1];
    url    = info[2];
    report = 'The certificate of the remote service is signed by the following untrusted Certificate Authority:\n\n';
    report += 'Issuer: ' + issuer + '\n';
    if( url && url != "none" ) report += 'Reference: ' + url + '\n';
    report += cert_summary( key:key );
    security_message( data:report, port:port );
  }
  exit( 0 );
}

exit ( 99 );
