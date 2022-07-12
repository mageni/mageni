###############################################################################
# OpenVAS Vulnerability Test
#
# Podcast Generator Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100134");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Podcast Generator Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://podcastgen.sourceforge.net/");

  script_tag(name:"summary", value:"This host is running Podcast Generator, a free web based podcast
  publishing script written in PHP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/podcast", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/index.php", port:port );
  if( isnull( buf ) ) continue;

  if( egrep( pattern:'Powered by <a [^>]+>Podcast Generator</a>', string:buf, icase:TRUE ) ) {

    vers = "unknown";

    version = eregmatch( string:buf, pattern:'<meta name="Generator" content="Podcast Generator ([0-9.]+[a-z ]*[0-9]*)"', icase:TRUE );
    if( ! isnull( version[1] ) ) vers = chomp( version[1] );

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/podcast_generator", value:tmp_version );
    set_kb_item( name:"podcast_generator/detected", value:TRUE );

    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)([a-z 0-9]+)?", base:"cpe:/a:podcast_generator:podcast_generator:");
    if( isnull( cpe ) )
      cpe = "cpe:/a:podcast_generator:podcast_generator";

    register_product( cpe:cpe, location:install, port:port );
    log_message( data:build_detection_report( app:"Podcast Generator",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
