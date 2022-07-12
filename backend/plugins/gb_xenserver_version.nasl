###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_version.nasl 7823 2017-11-20 08:54:04Z cfischer $
#
# Citrix XenServer Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105144");
  script_version("$Revision: 7823 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2014-12-18 17:03:13 +0100 (Thu, 18 Dec 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Citrix XenServer Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("xenserver/installed");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script performs SSH based detection of Citrix XenServer");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

soc = ssh_login_or_reuse_connection();
if( ! soc ) exit( 0 );

inventory = ssh_cmd( socket:soc, cmd:"cat /etc/xensource-inventory" );
if( "BUILD_NUMBER" >!< inventory || "PRODUCT_VERSION" >!< inventory ) exit( 0 );

product_version = 'unknown';
pversion = eregmatch( pattern:"PRODUCT_VERSION='([^']+)'", string:inventory );
if( ! isnull( pversion[1] ) ) product_version = pversion[1];

build_number = 'unknown';
bn = eregmatch( pattern:"BUILD_NUMBER='([^']+)'", string:inventory );
if( ! isnull( bn[1] ) ) build_number = bn[1];

xen_version = 'unknown';
xv = eregmatch( pattern:"XEN_VERSION='([^']+)'", string:inventory );
if( ! isnull( xv[1] ) ) xen_version = xv[1];

platform_version = 'unknown';
pv = eregmatch( pattern:"PLATFORM_VERSION='([^']+)'", string:inventory );
if( ! isnull( pv[1] ) ) platform_version = pv[1];

kernel_version = 'unknown';
kv = eregmatch( pattern:"KERNEL_VERSION='([^']+)'", string:inventory );
if( ! isnull( kv[1] ) ) kernel_version = kv[1];

control_domain_uuid = 'unknown';
cdu = eregmatch( pattern:"CONTROL_DOMAIN_UUID='([^']+)'", string:inventory );
if( ! isnull( cdu[1] ) ) control_domain_uuid = cdu[1];

p = ssh_cmd( socket:soc, cmd:"xe patch-list params=name-label,hosts" );
if( "name-label" >< p )
{
  lines = split( p, keep:FALSE );

  for( x=0; x < max_index( lines ); x++ )
  {
    if( lines[ x ] =~ "name-label" )
    {
      if( lines[ x + 1 ] =~ 'hosts.*: $' ) # hotfix was uploaded but not installed. handle it like a missing hotfix
      {
        patch_uploaded_but_not_applied += lines[ x ] + '\n';
        continue;
      }
      patches += lines[ x ] + '\n';
    }
  }
}

close( soc );

if( ! patches ) patches = 'No hotfixes installed';

set_kb_item( name:"xenserver/patches",             value:patches );
set_kb_item( name:"xenserver/product_version",     value:product_version );
set_kb_item( name:"xenserver/build_number",        value:build_number );
set_kb_item( name:"xenserver/xen_version",         value:xen_version );
set_kb_item( name:"xenserver/platform_version",    value:platform_version );
set_kb_item( name:"xenserver/kernel_version",      value:kernel_version );
set_kb_item( name:"xenserver/control_domain_uuid", value:control_domain_uuid );

if( patch_uploaded_but_not_applied ) set_kb_item( name:"xenserver/patch_uploaded_but_not_applied", value:patch_uploaded_but_not_applied );

register_and_report_os( os:"Citrix XenServer " + product_version + '-' + build_number, cpe:"cpe:/o:xen:xen:" + xen_version, banner_type:"SSH login", desc:"Citrix XenServer Detection", runs_key:"unixoide" );

cpe = 'cpe:/a:citrix:xenserver:' + product_version + '_' + build_number;
register_product( cpe:cpe, location:'ssh' ); # ex: 6.2.0_70446c

report = 'Detected Citrix XenServer version ' +  product_version + '-' + build_number + ' (ssh)\n' +
         'CPE: cpe:/a:citrix:xenserver:' + product_version + '_' + build_number + '\n' +
         'CPE: cpe:/o:xen:xen:' + xen_version + '\n\n' +
         'List of installed hotfixes: \n\n' + patches;

if( patch_uploaded_but_not_applied ) report += '\n\nHotfixes uploaded but not installed:\n\n' + patch_uploaded_but_not_applied + '\n';

log_message( port:0, data: report );

exit( 0 );

