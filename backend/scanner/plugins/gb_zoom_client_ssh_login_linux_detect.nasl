# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117715");
  script_version("2021-10-13T08:20:05+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-13 11:12:06 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-12 14:46:51 +0000 (Tue, 12 Oct 2021)");
  script_name("Zoom Client Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rpms_or_debs/gathered");

  script_tag(name:"summary", value:"SSH login-based detection of the Zoom Client.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

rpms = get_kb_item( "ssh/login/rpms" );
if( rpms && rpms =~ ";zoom~" ) {
  # e.g.:
  # ;zoom~5.8.0.16~1;
  vers = eregmatch( pattern:";zoom~([0-9.]+)", string:rpms );
  if( vers[1] ) {
    version = vers[1];
    concluded = "RPM package query: " + str_replace( string:vers[0], find:";", replace:"" );
  }
}

if( ! version ) {
  debs = get_kb_item( "ssh/login/packages" );
  if( debs && debs =~ "zoom.+Zoom Cloud Meetings" ) {
    # e.g.:
    # ii  zoom  5.8.0.16  amd64  Zoom Cloud Meetings
    vers = eregmatch( pattern:'ii\\s+zoom\\s+([0-9.]+)[^\r\n]+', string:debs );
    if( vers[1] ) {
      version = vers[1];
      concluded = "DPKG package query: " + vers[0];
    }
  }
}

if( version ) {

  # nb: Hard coded install path for RPM and DEB based installations. As we don't have a "--version"
  # parameter provided by the zoom binary and also no other means of a detection (at least currently)
  # we need to do the detection based on package manager installation (rpm and dpkg). We're currently
  # only detecting installations based on those installation methods and can use this hard coded path
  # here (The path was checked for Debian and CentOS install packages and both used the same path).
  path = "/opt/zoom/zoom";

  set_kb_item( name:"zoom/client/detected", value:TRUE );
  set_kb_item( name:"zoom/client/lin/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:zoom:zoom:" );
  if( ! cpe )
    cpe = "cpe:/a:zoom:zoom";

  # nb: NVD is currently using two different CPEs because Zoom has some inconsistencies in
  # their client naming. We register both just to be sure.
  cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:zoom:meetings:" );
  if( ! cpe2 )
    cpe2 = "cpe:/a:zoom:meetings";

  register_product( cpe:cpe, location:path, service:"ssh-login", port:0 );
  register_product( cpe:cpe2, location:path, service:"ssh-login", port:0 );

  report = build_detection_report( app:"Zoom Client",
                                   version:version,
                                   install:path,
                                   cpe:cpe,
                                   concluded:concluded );

  log_message( port:0, data:report );
}

exit( 0 );