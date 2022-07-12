###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_version_ssh.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# Cisco IOS XE Software Version Detection (ssh)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105658");
  script_version("$Revision: 10908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-05-09 15:41:31 +0200 (Mon, 09 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Cisco IOS XE Software Version Detection (ssh)");

  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_tag(name:"summary", value:"Get Cisco IOS XE Software Version via SSH.");
  script_dependencies("gb_cisco_show_version.nasl");
  script_mandatory_keys("cisco/show_version");
  exit(0);
}

include("ssh_func.inc");
include("cisco_ios.inc");

source = "ssh";

if( ! show_ver = get_kb_item( "cisco/show_version" ) ) exit( 0 );

if( show_ver !~ 'IOS[ -]XE Software.*,' ) exit( 0 );

set_kb_item( name:'cisco/show_ver', value:show_ver );
set_kb_item( name:"cisco_ios_xe/detected", value:TRUE );

version = 'unknown';

sv = split( show_ver, keep:FALSE );

foreach line ( sv )
{
  if( line =~ '^.*IOS[ -](XE)?.*Version( Denali)? [0-9.]+' )
  {
    vers = eregmatch( pattern:"Version( Denali)? ([^ ,\r\n]+)", string: line );
    break;
  }
}

if( ! isnull( vers[2] ) )
{
  version = vers[2];
  set_kb_item( name:"cisco_ios_xe/" + source + "/real_version", value:version );
  version = iosver_2_iosxe_ver( iosver:version );
  set_kb_item( name:'cisco_ios_xe/' + source + '/version', value:version );
}

if( show_ver =~ 'Cisco IOS Software, ASR[0-9]+' )
{
  m = eregmatch( pattern:'Cisco IOS Software, ASR([0-9]+)', string:show_ver );
  if( ! isnull( m[1] ) )
    set_kb_item( name:'cisco_ios_xe/' + source + '/model', value:'ASR' + m[1] );
}
else
{
  model = eregmatch( pattern: "cisco ([^\(]+) \([^\)]+\) processor", string: show_ver );
  if( ! isnull( model[1] ) )
  {
    set_kb_item( name:'cisco_ios_xe/' + source + '/model', value:model[1] );
  }
}

image = eregmatch( pattern: "\(([^)]+)\), *Version", string: show_ver);
if( ! isnull( image[1] ) )
{
  set_kb_item( name:'cisco_ios_xe/' + source + '/image', value:image[1] );
}

exit( 0 );

