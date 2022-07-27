###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_email_gateway_version.nasl 5709 2017-03-24 08:56:58Z cfi $
#
# McAfee Email Gateway Version
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105155");
  script_version("$Revision: 5709 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-24 09:56:58 +0100 (Fri, 24 Mar 2017) $");
  script_tag(name:"creation_date", value:"2015-01-07 16:37:56 +0100 (Wed, 07 Jan 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("McAfee Email Gateway Version");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("mcafee/OS");

  script_tag(name:"summary", value:"This script performs SSH based detection of McAfee Email Gateway");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("ssh_func.inc");
include("host_details.inc");

infos = ssh_cmd_exec( cmd:'cat /.build' );

if( "s.label.product Email Gateway" >!< infos || "s.labelshort.vendor McAfee" >!< infos  ) exit( 0 );

set_kb_item( name:"mcafee_email_gateway/LSC", value:TRUE );

product_version = eregmatch( pattern:'s.product.version ([^\r\n]+)', string:infos );
product_build   = eregmatch( pattern:'s.product.build ([^\r\n]+)', string:infos );
product_package = eregmatch( pattern:'s.product.package ([^\r\n]+)', string:infos );
product_name    = eregmatch( pattern:'s.label.product ([^\r\n]+)', string:infos );

if( ! isnull( product_version[1] ) )
{
  set_kb_item( name:'mcafee_email_gateway/product_version', value:product_version[1] );
  version += product_version[1];
}

if( ! isnull( product_build[1] ) )
{
  set_kb_item( name:'mcafee_email_gateway/product_build', value:product_build[1] );
  version += '.' + product_build[1];
}

if( ! isnull( product_package[1] ) )
{
  set_kb_item( name:'mcafee_email_gateway/product_package', value:product_package[1] );
  version += '.' + product_package[1];
}

product = 'McAfee Email Gateway';
if( ! isnull( product_name[1] ) )
  product = product_name[1];

set_kb_item( name:'mcafee_email_gateway/product_name', value:product );

foreach line ( split( infos ) )
{
 if( installed_patch = eregmatch( pattern:'s.product.patch.([^ ]+)', string:line ) )
 {
   patches += installed_patch[1] + ' ';
   report_patches += installed_patch[1] + '\n';
 }
}

if( patches )
  set_kb_item( name:"mcafee_email_gateway/patches", value:patches );

os = ssh_cmd_exec( cmd:'cat /.mlos-version' );

if( "McAfee Linux Operating System" >< os )
{
  os_version = 'unknown';
  os_vers = eregmatch( pattern:'Version: ([^\r\n]+)', string:os );

  if( ! isnull( os_vers[1] ) )
    os_version = os_vers[1];

  os_cpe_vers = str_replace( string:os_version, find:"-", replace:"_" );

  register_and_report_os( os:"McAfee Linux Operating System (" + os_version + ")", cpe:"cpe:/o:mcafee:linux_operating_system:" + os_cpe_vers, banner_type:"SSH login", desc:"McAfee Email Gateway Version", runs_key:"unixoide" );
}

cpe = 'cpe:/a:mcafee:email_gateway';
if( version != 'unknown' )
  cpe += ':' + version;

register_product( cpe:cpe, location:'ssh' );

report = 'Detected McAfee ' + product  + ' (ssh)\n' +
         'Version: ' +  version + '\n' +
         'CPE: ' + cpe + '\n';

if( patches )
  report += '\nList of installed patches: \n\n' + report_patches;

log_message( port:0, data: report );
exit( 0 );

