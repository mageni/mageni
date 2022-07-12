###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_cms_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# Moodle CMS Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Modified 2009-03-25 Michael Meyer
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
  script_oid("1.3.6.1.4.1.25623.1.0.800239");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10891 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Moodle CMS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://moodle.org/");

  script_tag(name:"summary", value:"This host is running moodle.
  Moodle is a Course Management System (CMS), also known as a Learning
  Management System (LMS) or a Virtual Learning Environment (VLE). It
  is a Free web application that educators can use to create effective
  online learning sites.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/moodle", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( egrep(pattern: "^Set-Cookie: MoodleSession", string:rcvRes ) ||
      egrep(pattern: '<a [^>]*href="http://moodle\\.org/"[^>]*><img [^>]*src="pix/moodlelogo.gif"', string:rcvRes) ) {

    set_kb_item( name: "moodle/detected", value: TRUE );

    version = "unknown";

    ver = eregmatch( string: rcvRes, pattern: "title=.Moodle ([0-9.]+)\+*.*[(Build: 0-9)]*" );

    if( ! isnull( ver[1] ) ) {
      version = ver[1];
    } else {
      # Last version listed in /admin/environment.xml is the current version
      req = http_get( port: port, item: dir + "/admin/environment.xml" );
      resp = http_keepalive_send_recv( port: port, data: req );
      while(TRUE){
        ver = eregmatch( string: resp, pattern: '<MOODLE version="([0-9.]+)"' );
        if( isnull( ver[1] ) ) {
          break;
        }
        final_ver = ver;
        resp = ereg_replace( pattern: '<MOODLE version="' + ver[1] + '"', string: resp, replace: "None" );
      }
      ver = final_ver;
      if( ! isnull( ver[1] ) ) {
        version = ver[1];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/moodle", value:tmp_version );
    set_kb_item( name:"Moodle/Version", value:version );

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:moodle:moodle:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:moodle:moodle';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"moodle",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
