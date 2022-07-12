###############################################################################
# OpenVAS Vulnerability Test
#
# Sensiolabs Symfony Detection Consolidation
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107325");
  script_version("2019-05-23T07:09:57+0000");
  script_tag(name:"last_modification", value:"2019-05-23 07:09:57 +0000 (Thu, 23 May 2019)");
  script_tag(name:"creation_date", value:"2018-06-26 16:20:53 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sensiolabs Symfony Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_symfony_http_detect.nasl", "gb_symfony_ssh_login_detect.nasl");
  script_mandatory_keys("symfony/detected");

  script_xref(name:"URL", value:"https://symfony.com/");

  script_tag(name:"summary", value:"The script reports a detected Sensiolabs Symfony including the
  version number.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "symfony/detected" ) ) exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "ssh-login", "http" ) ) {

  install_list = get_kb_list( "symfony/" + source + "/*/installs" );

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 ) continue; # Something went wrong and not all required infos are there...

    port = infos[0];
    install = infos[1];
    version = infos[2];
    concluded = infos[3];
    concludedUrl = infos[4];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sensiolabs:symfony:" );
    if( ! cpe )
      cpe = "cpe:/a:sensiolabs:symfony";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"Sensiolabs Symfony Framework",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concludedUrl:concludedUrl,
                                      concluded:concluded );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );
