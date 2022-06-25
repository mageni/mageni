###############################################################################
# OpenVAS Vulnerability Test
# $Id: external_svc_ident.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# external services identification
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# We could do this job in amap.nasl or nmap.nasl, but as those
# plugins must be signed to be "trusted", we don't want to change them often

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14664");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_copyright("(C) 2004 Michel Arboi");
  script_name("external services identification");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_dependencies("secpod_open_tcp_ports.nasl", "gb_open_udp_ports.nasl");
  script_mandatory_keys("external_svc_ident/available");

  script_tag(name:"summary", value:"This plugin performs service detection.

  Description :

  This plugin registers services that were identified
  by external scanners (amap, nmap, etc...).

  It does not perform any fingerprinting by itself.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");


amapcvt['http'] = 'www';
amapcvt['http-proxy'] = 'http_proxy';
amapcvt['rsyncd'] = 'rsync';
amapcvt['x-windows'] = 'X11';
amapcvt['ms-distribution-transport'] = 'msdtc';

nmapcvt['http'] = 'www';
nmapcvt['http-proxy'] = 'http_proxy';

foreach ipp( make_list( 'tcp', 'udp' ) ) {

  ports = get_kb_list( toupper( ipp ) + '/PORTS' );

  if( ! isnull( ports ) ) {

    foreach port ( ports ) {
      s = get_kb_item( 'Amap/' + ipp + '/' + port + '/Svc' );
      banner = get_kb_item( 'Amap/' + ipp + '/' + port + '/FullBanner');
      if( ! banner ) banner = get_kb_item( 'Amap/' + ipp + '/' + port + '/PrintableBanner' );
      svc = NULL;

      if( s && s != 'ssl' && s != 'unindentified' ) {
        svc = amapcvt[s];
        if( ! svc ) {
          if( match( string:s, pattern:'dns-*' ) ) {
            svc = 'dns';	# not used yet
          } else if ( match( string:s, pattern:'http-*' ) ) {
            svc = 'www';
          } else if ( match( string:s, pattern:'nntp-*' ) ) {
            svc = 'nntp';
          } else if( match( string:s, pattern:'ssh-*' ) ) {
            svc = 'ssh';
          } else {
            svc = s;
          }
        }
        # Now let's check some suspicious services
        if( s == 'echo' && ipp == 'tcp' ) {
          soc = open_sock_tcp(port);
          if( ! soc ) {
            svc = NULL;
          } else {
            str = rand_str() + '\n';
            send( socket:soc, data:str );
            b = recv( socket:soc, length:1024 );
            if( b != str ) svc = NULL;
            close( soc );
          }
        }
      } else {
        s = get_kb_item( 'Nmap/' + ipp + '/' + port + '/svc' );
        if( s ) {
          svc = amapcvt[s];
          if( ! svc )	# we probably need some processing...
          svc = s;
        }
      }
      if( svc ) {
        register_service( port:port, proto:svc, ipproto:ipp );
      } else if( b ) {
        set_unknown_banner( port:port, banner:b, ipproto:ipp );
      }
    }
  }
}

exit( 0 );