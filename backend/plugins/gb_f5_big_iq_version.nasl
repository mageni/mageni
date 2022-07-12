###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_f5_big_iq_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# F5 Networks BIG-IQ Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105164");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-12 14:32:58 +0100 (Mon, 12 Jan 2015)");
  script_name("F5 Networks BIG-IQ Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of F5 Networks BIG-IQ");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("f5/big_iq/VERSION_RAW");
  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

infos = get_kb_item( "f5/big_iq/VERSION_RAW" );

if( "Product: BIG-IQ" >!< infos ) exit( 0 );

if( get_kb_item("f5/shell_is_tmsh") )
  nosh = TRUE;

_version = 'unknown';
_build = 'unknown';

version = eregmatch( pattern:'Version: ([^\r\n]+)', string:infos );
build   = eregmatch( pattern:'Build: ([^\r\n]+)', string:infos );
built   = eregmatch( pattern:'Built: ([^\r\n]+)', string:infos );
edition = eregmatch( pattern:'Edition: ([^\r\n]+)', string:infos );
changelist = eregmatch( pattern:'Changelist: ([^\r\n]+)', string:infos );

if( ! isnull( version[1] ) )
{
  _version = version[1];
  set_kb_item( name:'f5/big_iq/version', value:_version );
}

if( ! isnull( build[1] ) )
{
  _build = build[1];
  set_kb_item( name:'f5/big_iq/build', value:_build );
}

if( ! isnull( edition[1] ) )
  set_kb_item( name:'f5/big_iq/edition', value:edition[1] );

if( ! isnull( built[1] ) )
  set_kb_item( name:'f5/big_ip/built', value:built[1] );

if( ! isnull( changelist[1] ) )
  set_kb_item( name:'f5/big_iq/changelist', value:changelist[1] );

if( nosh )
   modules_cmd = ssh_cmd_exec( cmd:'list sys provision', nosh:TRUE );
else
   modules_cmd = ssh_cmd_exec( cmd:'tmsh list sys provision' );

if( ! isnull( modules_cmd ) )
{
  modules_lines = split( modules_cmd );
  for( i = 0; i < max_index( modules_lines ); i++ )
  {
    if( "{ }" >< modules_lines[i] ) continue;
    if( module = eregmatch( pattern:'sys provision ([^ \r\n{]+) \\{[\r\n]+', string:modules_lines[i] ) )
      active_modules += module[1] + ',';
  }
}

if( active_modules =~ ',$' ) active_modules = ereg_replace( pattern:'(,)$', replace:'', string:active_modules );
active_modules = toupper( active_modules );

if( active_modules )
  set_kb_item( name:'f5/big_ip/active_modules', value:active_modules );

cpe = 'cpe:/h:f5:big-iq';

if( _version != 'unknown' )
  cpe += ':' + _version;

register_product( cpe:cpe, location:'ssh' );

report = 'Detected F5 BIG-IQ (ssh)\n' +
         'Version: ' + _version + '\n' +
         'Build: ' + _build + '\n';

if( active_modules )
  report += 'Modules: ' + active_modules + '\n';

log_message( port:0, data: report );
exit( 0 );

