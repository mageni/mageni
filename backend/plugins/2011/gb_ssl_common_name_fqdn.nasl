###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssl_common_name_fqdn.nasl 8981 2018-02-28 12:15:33Z cfischer $
#
# SSL/TLS: Certificate - Subject Common Name Does Not Match Server FQDN
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103141");
  script_version("$Revision: 8981 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-28 13:15:33 +0100 (Wed, 28 Feb 2018) $");
  script_tag(name:"creation_date", value:"2011-04-27 15:13:59 +0200 (Wed, 27 Apr 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSL/TLS: Certificate - Subject Common Name Does Not Match Server FQDN");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("ssl_cert_details.nasl");
  script_mandatory_keys("ssl/cert/avail");

  script_tag(name:"summary", value:"The SSL/TLS certificate contains a common name (CN) that does not match the hostname.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");
include("misc_func.inc");
include("byte_func.inc");
include("global_settings.inc");

# List of keys where the CN doesn't match the FQDN
problematic_keys = make_array();

hostname = get_host_name();
ip = get_host_ip();

if( hostname == ip ) exit( 0 );

# It makes no sense to report a wrong CN for localhost/127.0.0.1
if( hostname == "localhost" || ip == "127.0.0.1" ) exit( 0 );

ssls = get_kb_list( "HostDetails/SSLInfo/*" );

if( ! isnull( ssls ) ) {

  foreach key( keys( ssls ) ) {

    tmp = split( key, sep:"/", keep:FALSE );
    port = tmp[2];
    vhost = tmp[3];

    fprlist = get_kb_item( key );
    if( ! fprlist ) continue;

    tmpfpr = split( fprlist, sep:",", keep:FALSE );
    fpr = tmpfpr[0];

    if( fpr[0] == "[" ) {
      debug_print( "A SSL/TLS certificate on port ", port, " (" + vhost + ")",
                   " is erroneous.", level:0 );
      continue;
    }

    key = "HostDetails/Cert/" + fpr + "/";

    hostnames = get_kb_item( key + "hostnames" );
    if( isnull( hostnames ) ) continue;

    hostnamelist = split( hostnames, sep:",", keep:FALSE );
    if( isnull( hostnamelist ) ) continue; # No hostname identified in cert

    if( ! in_array( search:hostname, array:hostnamelist ) ) {

      notVuln = FALSE;

      foreach tmphostname( hostnamelist ) {

        comname = tmphostname;

        if( comname[0] == "*" ) {
          hn = stridx( hostname, "." );
          in = stridx( tmphostname, "." );
          if( ( hn > 0 && in > 0 ) && substr( hostname, hn ) == substr( tmphostname, in ) ) {
            notVuln = TRUE;
            continue;
          }

          hn = comname - '*.';
          if( hn == hostname ) {
            notVuln = TRUE;
            continue;
          }
        }
      }
      if( ! notVuln ) problematic_keys[port] = key;
    }
  }

  foreach port( keys( problematic_keys ) ) {
    report = 'The certificate of the remote service contains a common name (CN) that does not match the hostname "' + hostname + '".\n';
    report += cert_summary( key:problematic_keys[port] );
    log_message( data:report, port:port );
  }

  exit( 0 );
}

exit( 99 );
