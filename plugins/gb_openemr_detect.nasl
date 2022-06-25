###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openemr_detect.nasl 11594 2018-09-25 09:00:11Z asteins $
#
# OpenEMR Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.103018");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11594 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 11:00:11 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2011-01-07 13:52:38 +0100 (Fri, 07 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenEMR Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.oemr.org/");

  script_tag(name:"summary", value:"This host is running OpenEMR, a free medical practice management,
  electronic medical records, prescription writing, and medical billing application.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/openemr", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/interface/login/login.php';
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf =~ "HTTP/1.. 200" && "OpenEMR" >< buf ) {

    set_kb_item( name:"openemr/installed", value:TRUE );

    version = "unknown";
    ver = eregmatch( pattern:'<div class="version">[\r\n ]*v([0-9dev (.-]+)', string:buf );

    if (isnull(ver[1])) {
      url = dir + "/admin.php";
      req = http_get(item: url, port: port);
      buf = http_keepalive_send_recv(port: port, data: req);

      ## the following regex is matching to this (for example): "<td>5.0.0 (3)</td><td><a href="[...]">Log In</a></td>"
      ver = eregmatch(pattern: "<td>([0-9dev (.-]+)\)?</td>.*Log In</a></td>", string: buf);
    }

    if( isnull( ver[1] ) ) {

      url = dir +  "/interface/login/login_title.php";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      ver = eregmatch( string:buf, pattern:"OpenEMR[^=/]+.*v([0-9dev (.-]+)", icase:TRUE );
    }

    if ( ! isnull( ver[1] ) ) {
      version = ereg_replace(pattern: " \(", string: ver[1], replace: "-");
      set_kb_item(name: "openemr/version", value: version);
    }

    # replaced until get_version_from_cpe() is being fixed
    # cpe = build_cpe( value:version, exp:"^([0-9dev.]+)-?([0-9])?", base:"cpe:/a:open-emr:openemr:" );
    cpe = build_cpe( value:version, exp:"^([0-9dev\.\-]+)", base:"cpe:/a:open-emr:openemr:" );

    if( ! cpe )
      cpe = 'cpe:/a:open-emr:openemr';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"OpenEMR",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
