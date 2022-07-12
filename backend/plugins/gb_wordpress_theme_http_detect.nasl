# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112798");
  script_version("2020-08-10T13:48:35+0000");
  script_tag(name:"last_modification", value:"2020-08-11 10:23:00 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-06 12:04:11 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WordPress Theme Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"Checks and reports which WordPress themes are installed on the target system.");

  script_xref(name:"URL", value:"https://wordpress.org/themes/");

  script_timeout(900);

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

if( ! port = get_app_port( cpe: CPE, service: "www" ) ) exit( 0 );
if( ! dir = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( dir == "/" ) dir = "";

#nb: The format is: "[STYLE_URL]", "[NAME]#---#[DETECTION PATTERN]#---#[VERSION REGEX]#---#[CPE]#--#[THEME URL (optional)]"
themes = make_array(
"Divi/style.css", "Elegant Themes Divi#---#Theme Name: Divi#---#Version: ([0-9.]+)#---#cpe:/a:elegantthemes:divi#---#https://www.elegantthemes.com/gallery/divi/",
"Extra/style.css", "Elegant Themes Extra#---#Theme Name: Extra#---#Version: ([0-9.]+)#---#cpe:/a:elegantthemes:extra#---#https://www.elegantthemes.com/gallery/extra/"
);

foreach style( keys( themes ) ) {

  infos = themes[style];
  if( ! infos )
    continue;

  infos = split( infos, sep: "#---#", keep: FALSE );
  if( ! infos || max_index( infos ) < 4 )
    continue;

  name = infos[0];
  detect_regex = infos[1];
  vers_regex = infos[2];
  cpe = infos[3] + ":";
  theme_url = infos[4];
  extra = "";

  url = dir + "/wp-content/themes/" + style;
  res = http_get_cache( port: port, item: url );
  if( egrep( pattern: detect_regex, string: res, icase: TRUE ) && "Theme URI:" >< res ) {
    vers = eregmatch( pattern: vers_regex, string: res, icase: TRUE );
    if( ! vers[1] )
      continue;

    version = vers[1];

    kb_entry_name = ereg_replace( pattern: "/style.css", string: tolower( style ), replace: "", icase: TRUE );
    insloc = ereg_replace( pattern: "/style.css", string: url, replace: "", icase: TRUE );

    set_kb_item( name: "wordpress/theme/" + kb_entry_name + "/detected", value: TRUE );

    if( theme_url )
      extra = "Theme Page: " + theme_url;
    else
      extra = "Theme Page: https://wordpress.org/themes/" + kb_entry_name + "/";

    register_and_report_cpe( app: name,
                             ver: version,
                             concluded: vers[0],
                             base: cpe,
                             expr: "([0-9.]+)",
                             insloc: insloc,
                             regPort: port,
                             regService: "www",
                             conclUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ),
                             extra: extra );
  }
}

exit( 0 );
