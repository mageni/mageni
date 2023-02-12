# Copyright (C) 2023 Greenbone Networks GmbH
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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104498");
  script_version("2023-01-20T10:11:50+0000");
  script_tag(name:"last_modification", value:"2023-01-20 10:11:50 +0000 (Fri, 20 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-18 10:20:43 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Control WebPanel / CentOS WebPanel (CWP) Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_cwp_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cwp_ssh_login_detect.nasl");
  script_mandatory_keys("centos_webpanel/detected");

  script_xref(name:"URL", value:"https://control-webpanel.com/");

  script_tag(name:"summary", value:"Consolidation of Control WebPanel / CentOS WebPanel (CWP)
  detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if( ! get_kb_item( "centos_webpanel/detected" ) )
  exit( 0 );

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

report = ""; # nb: To make openvas-nasl-lint happy...

# nb: HTTP one isn't able to gather the version (currently)
foreach source( make_list( "http", "ssh-login" ) ) {

  if( ! install_list = get_kb_list( "centos_webpanel/" + source + "/*/installs" ) )
    continue;

  # nb:
  # - Note that sorting the array above is currently dropping the named array index
  # - Sorting is done to not report changes on delta reports if just the order is different
  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    conclUrl = infos[4];

    cpe = build_cpe( value:version, exp:"^([0-9a-z.]+)", base:"cpe:/a:centos-webpanel:centos_web_panel:" );
    if( ! cpe )
      cpe = "cpe:/a:centos-webpanel:centos_web_panel";

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:"Control WebPanel / CentOS WebPanel (CWP)", version:version, install:install, cpe:cpe, concluded:concl, concludedUrl:conclUrl );
  }
}

if( report ) {

  log_message( port:0, data:report );

  # nb: Only runs on these OS variants according to https://control-webpanel.com/installation-instructions#step2
  os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", desc:"Control WebPanel / CentOS WebPanel (CWP) Detection Consolidation", runs_key:"unixoide" );
  os_register_and_report( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", desc:"Control WebPanel / CentOS WebPanel (CWP) Detection Consolidation", runs_key:"unixoide" );
  os_register_and_report( os:"Rocky Linux", cpe:"cpe:/o:rocky:rocky", desc:"Control WebPanel / CentOS WebPanel (CWP) Detection Consolidation", runs_key:"unixoide" );
  os_register_and_report( os:"Alma Linux", cpe:"cpe:/o:almalinux:almalinux", desc:"Control WebPanel / CentOS WebPanel (CWP) Detection Consolidation", runs_key:"unixoide" );
  os_register_and_report( os:"Oracle Linux", cpe:"cpe:/o:oracle:linux", desc:"Control WebPanel / CentOS WebPanel (CWP) Detection Consolidation", runs_key:"unixoide" );
}

exit( 0 );
