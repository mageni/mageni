# Copyright (C) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105621");
  script_version("2023-01-10T10:12:01+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-04-26 11:14:43 +0200 (Tue, 26 Apr 2016)");
  script_name("Sophos Cyberoam Central Console (CCC) Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Sophos Cyberoam Central Console
  (CCC).");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("sophos/cyberoam_central_console/version_info");

  exit(0);
}

include("host_details.inc");

if( ! sysinfo = get_kb_item( "sophos/cyberoam_central_console/version_info" ) )
  exit( 0 );

set_kb_item( name:"sophos/cyberoam_central_console/detected", value:TRUE );
set_kb_item( name:"sophos/cyberoam_central_console/ssh-login/detected", value:TRUE );

# Appliance Key:                                  N.A
# Public Key:                                     N.A
# CCC Model:                                      CCCVMS200
# CCC version:                                    02.00.2 build 018
# CCC Loader version:                             0x000003ec
# Config DB version:                              01.002
# IPS Signature Distribution version:             3.0.25
# Webcat Signature Distribution version:          -
# AntiVirus Signature Distribution version:       -
# Logging Daemon version:                         0.0.0.9
# Hot Fix version:                                N.A

cpe = "cpe:/a:cyberoam:cyberoam_central_console";
version = "unknown";
extra = "";
install = "/";

vers = eregmatch( pattern:"CCC version:\s*([0-9.]+[^ ]+) ", string:sysinfo );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  cpe += ":" + version;
}

mod = eregmatch( pattern:'CCC Model:\\s*(CCC[^ \r\n]+)', string:sysinfo );
if( ! isnull( mod[1] ) )
  set_kb_item( name:"sophos/cyberoam_central_console/model", value:mod[1] );

bld = eregmatch( pattern:'CCC version:\\s*[0-9.]+[^ ]+ build ([0-9]+[^ \r\n]+)', string:sysinfo );
if( ! isnull( bld[1] ) )
  set_kb_item( name:"sophos/cyberoam_central_console/build", value:bld[1] );

hf = eregmatch( pattern:'Hot Fix version:\\s*([^\r\n]+)', string:sysinfo );
if( ! isnull( hf[1] ) && hf[1] != "N.A" )
  set_kb_item( name:"sophos/cyberoam_central_console/hotfix", value:hf[1] );

register_product( cpe:cpe, location:install, port:0, service:"ssh-login" );

log_message( data:build_detection_report( app:"Sophos Cyberoam Central Console (CCC)", version:version, install:install,
                                          cpe:cpe, concluded:sysinfo ),
             port:0 );

exit( 0 );
