###############################################################################
# OpenVAS Vulnerability Test
#
# FortiMail Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105210");
  script_version("2020-07-06T11:45:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-07 10:15:52 +0000 (Tue, 07 Jul 2020)");
  script_tag(name:"creation_date", value:"2015-02-10 18:02:19 +0100 (Tue, 10 Feb 2015)");

  script_name("Fortinet FortiMail Detection (SSH-Login)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("FortiOS/system_status");

  script_tag(name:"summary", value:"SSH based detection of Fortinet FortiMail.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

system = get_kb_item("FortiOS/system_status");
if( !system || "FortiMail" >!< system )
  exit( 0 );

port = get_kb_item( "FortiOS/ssh-login/port" );

set_kb_item( name:"fortinet/fortimail/detected", value:TRUE );
set_kb_item( name:"fortinet/fortimail/ssh-login/detected", value:TRUE );
set_kb_item( name:"fortinet/fortimail/ssh-login/port", value:port );

model = eregmatch( string:system, pattern:"Version\s*:\s*(FortiMail-[^ ]+)" );

if( ! isnull( model[1] ) ) {
  mod = model[1];
  mod = chomp( mod );
  set_kb_item( name:"fortinet/fortimail/model", value:mod );
}

vers = "unknown";
version = eregmatch( string:system, pattern:"Version\s*:\s*FortiMail-[^ ]*\s*v([^,]+)" );

if( ! isnull( version[1] ) ) {
  ver = version[1];
  for( i = 0; i < strlen( ver ); i++ ) {
    if( ver[i] == "." )
      continue;

    v += ver[ i ];

    if( i < ( strlen( ver ) - 1 ) )
      v += '.';
  }

  vers = v;
  set_kb_item( name:"fortinet/fortimail/ssh-login/" + port + "/concluded", value:version[0] );
}

build = eregmatch( string:system, pattern:',build([^,]+)' );
if( ! isnull( build[1] ) ) {
  build = ereg_replace( string:build[1], pattern:'^0', replace:"" );
  set_kb_item( name:"fortinet/fortimail/build", value:build );
}

patch = eregmatch( string:system, pattern:"Patch ([0-9]+)" );
if( ! isnull( patch[1] ) ) {
  set_kb_item( name:"fortinet/fortimail/patch", value:patch[1] );
}

set_kb_item( name:"fortinet/fortimail/ssh-login/" + port + "/version", value:vers );

exit( 0 );
