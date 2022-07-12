###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortios_detect.nasl 9608 2018-04-25 13:33:05Z jschulte $
#
# FortiOS Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105313");
  script_version("$Revision: 9608 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 15:33:05 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-07-03 10:42:08 +0200 (Fri, 03 Jul 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("FortiOS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Fortinet-Devices running FortiOS");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port( default:443 );

hashes = '3955ddaf1229f63f94f4a20781b3ade4
          2719cca465341edf55be52939058893e
          5ed607103738fa9c2788e0f51567bdb8
          8f5018acd4cdeb6a6122e51006a53e86
          77759f22e8c2a847f655dba3d6013555
          29f7a3d0bc4da0e0a636e31e6a670d31
          7c1fd3cd595862f26d1460037cbec76a
          d3b30398ae57327dfdae2293d7da6f08';

urls = make_list( "/images/logon_merge.gif",
                  "/resource/images/logon_t.gif",
                  "/resource/images/logon.gif",
                  "/customviews/image/login_bg/",
                  "/images/login_top.gif",
                  "/theme1/images/logo.gif",
                  "/images/logo.gif" );

foreach url ( urls )
{
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "GIF89" >!< buf ) continue;

  hash = hexstr( MD5( buf ) );

  if( hash >< hashes )
  {
    cpe = 'cpe:/o:fortinet:fortios';
    register_and_report_os( os:"FortiOS", cpe:cpe, banner_type:"HTTP banner", port:port, desc:"FortiOS Detection", runs_key:"unixoide" );
    log_message( port:port, data:'The remote host is a Fortinet-Device running FortiOS\nCPE: ' + cpe);
    exit( 0 );
  }
}

exit( 0 );


