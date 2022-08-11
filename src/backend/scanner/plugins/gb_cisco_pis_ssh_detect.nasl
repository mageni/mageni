###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_pis_ssh_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Prime Infrastructure Detection (SSH)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105612");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-20 15:22:13 +0200 (Wed, 20 Apr 2016)");
  script_name("Cisco Prime Infrastructure Detection (SSH)");

  script_tag(name:"summary", value:"This Script performs SSH based detection of Cisco Prime Infrastructure");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_pis/show_ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

source = "ssh";

if( ! system = get_kb_item( "cisco_pis/show_ver" ) ) exit( 0 );

if( "Cisco Prime Infrastructure" >!< system ) exit( 0 );

set_kb_item( name:"cisco/pis/detected", value:TRUE );

cpe = 'cpe:/a:cisco:prime_infrastructure';
vers = 'unknown';

# Cisco Application Deployment Engine OS Release: 2.3
# ADE-OS Build Version: 2.3.0.101-root
# ADE-OS System Architecture: x86_64
#
# Copyright (c) 2005-2010 by Cisco Systems, Inc.
# All rights reserved.
# Hostname: cpi
#
#
# Version information of installed applications
# ---------------------------------------------
#
# Cisco Prime Infrastructure
# ********************************************************
# Version : 3.0.0
# Build : 3.0.0.0.78
# Critical Fixes:
#         PI 3.0.3 ( 3.0.0 )
# Prime Add-Ons:
#         Prime Insight Agent ( 1.0.0 )

lines = split( system );
foreach line ( lines )
{
  system -= line;
  if( "Cisco Prime Infrastructure" >< line ) break;
}

version = eregmatch( pattern:'Version\\s*:\\s*([0-9]+[^\r\n]+)', string:system );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

_build = eregmatch( pattern:'Build\\s*:\\s*([0-9]+[^\r\n]+)', string:system );
if( ! isnull( _build[1] ) )
{
  build =  _build[1];
  set_kb_item( name:"cisco_pis/" + source + "/build", value:build );
}

if( "Critical Fixes:" >< system )
{
  lines = split( system );
  foreach line ( lines )
  {
    system -= line;
    if( "Critical Fixes:" >< line ) break;
  }

  lines = split( system );
  foreach line ( lines )
  {
    if( "TECH PACK" >< line ) continue;
    if( line =~ 'PI [0-9]+' )
    {
      _p = eregmatch( pattern:'PI ([0-9]+[^ \r\n(]+) ', string:line );
      if( ! isnull( _p[1] ) )
      {
        installed_patches += 'PI ' + _p[1] + '\n';
        if(  "Update" >< _p[1]  )
        {
          pa = eregmatch( pattern:'(^[0-9.]+ )', string:_p[1] );
          if( ! isnull( pa[1] ) )
            _p[1] = pa[1];
        }
        if( ! max_patch_version ) max_patch_version = _p[1];
        else
          if( version_is_less( version:max_patch_version, test_version:_p[1] ) ) max_patch_version = _p[1];
      }
    }
    else
      break;
  }
}

if( max_patch_version )
{
  set_kb_item( name:"cisco_pis/" + source + "/max_patch_version", value:max_patch_version );
  vers = max_patch_version;
}
else
  set_kb_item( name:"cisco_pis/" + source + "/max_patch_version", value:"0" );

set_kb_item( name:"cisco_pis/" + source + "/version", value:vers );

if( installed_patches )  set_kb_item( name:"cisco_pis/" + source + "/installed_patches", value:installed_patches );

report = 'Detected Cisco Prime Infrastructure\n' +
         'Version: ' + vers + '\n' +
         'Location: ' + source + '\n' +
         'CPE: ' + cpe + '\n' +
         'Concluded: "' + version[0] + '"';

if( build ) report += '\nBuild: ' + build;
if( max_patch_version ) report += '\nMax patch version installed: PI ' + max_patch_version;
if( installed_patches ) report += '\n\nInstalled patches:\n' + installed_patches + '\n';

log_message( port:0, data:report );
exit( 0 );

