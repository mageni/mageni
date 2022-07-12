###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cyberoam_central_console_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cyberoam Central Console Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105621");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-26 11:14:43 +0200 (Tue, 26 Apr 2016)");
  script_name("Cyberoam Central Console Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cyberoam Central Console");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cyberoam_cc/version_info");
  exit(0);
}

include("host_details.inc");

if( ! sysinfo = get_kb_item( "cyberoam_cc/version_info" ) ) exit( 0 );
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

cpe = 'cpe:/a:cyberoam:cyberoam_central_console';
vers = 'unknown';

version = eregmatch( pattern:'CCC version:\\s*([0-9.]+[^ ]+) ', string:sysinfo );

if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
  set_kb_item( name:'cyberoam_cc/version', value:vers );
}

mod = eregmatch( pattern:'CCC Model:\\s*(CCC[^ \r\n]+)', string:sysinfo );
if( ! isnull( mod[1] ) )
{
  model = mod[1];
  set_kb_item( name:'cyberoam_cc/model', value:model );
}

_build = eregmatch( pattern:'CCC version:\\s*[0-9.]+[^ ]+ build ([0-9]+[^ \r\n]+)', string:sysinfo );
if( ! isnull( _build[1] ) )
{
  build = _build[1];
  set_kb_item( name:'cyberoam_cc/build', value:build );
}

hf = eregmatch( pattern:'Hot Fix version:\\s*([^\r\n]+)', string:sysinfo );
if( ! isnull( hf[1] ) && hf[1] != 'N.A' )
{
  hotfix = hf[1];
  set_kb_item( name:'cyberoam_cc/hotfix', value:hotfix );
}

register_product( cpe:cpe, location:'ssh' );

report = 'Detected Cyberoam Central Console\n' +
         'Version: ' + vers;

if( build )  report += '\nBuild:   ' + build;
if( model )  report += '\nModel:   ' + model;
if( hotfix ) report += '\nInstalled hostfix: ' + hotfix;

log_message( port:0, data:report );
exit( 0 );
