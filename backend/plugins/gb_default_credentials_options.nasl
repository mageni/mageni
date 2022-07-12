###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_default_credentials_options.nasl 13481 2019-02-05 18:48:16Z cfischer $
#
# Options for Brute Force NVTs
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103697");
  script_version("$Revision: 13481 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 19:48:16 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-04-15 10:23:42 +0200 (Mon, 15 Apr 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Options for Brute Force NVTs");
  script_category(ACT_SETTINGS);
  script_family("Settings");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");

  script_add_preference(name:"Credentials file:", value:"", type:"file");
  script_add_preference(name:"Use only credentials listed in uploaded file:", type:"checkbox", value:"yes");
  script_add_preference(name:"Disable brute force checks", type:"checkbox", value:"no");
  script_add_preference(name:"Disable default account checks", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This NVT set some options for the brute force credentials checks.

  - Disable brute force checks:

  Disables the brute force cecks done by the following NVTs:

  HTTP Brute Force Logins With Default Credentials (OID: 1.3.6.1.4.1.25623.1.0.108041)

  SSH Brute Force Logins With Default Credentials (OID: 1.3.6.1.4.1.25623.1.0.108013)

  SMB Brute Force Logins With Default Credentials (OID: 1.3.6.1.4.1.25623.1.0.804449)

  Check default community names of the SNMP Agent (OID: 1.3.6.1.4.1.25623.1.0.103914).

  - Disable default account checks:

  Disables all NVTs checking for default accounts (Mainly from the 'Default Accounts' family).

  - Credentials file:

  A file containing a list of credentials. One username/password pair per line. Username and password are separated
  by ':'. Please use 'none' for empty passwords or empty usernames. If the username or the password contains a ':',
  please escape it with '\:'.

  Examples:

  user:userpass

  user1:userpass1

  none:userpass2

  user3:none

  user4:pass\:word

  user5:userpass5

  - Use only credentials listed in uploaded file:

  Use only the credentials that are listed in the uploaded file. The internal default credentials are ignored.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

disable_bf = script_get_preference( "Disable brute force checks" );
if( "yes" >< disable_bf )
  set_kb_item( name:"default_credentials/disable_brute_force_checks", value:TRUE );

disable_da = script_get_preference( "Disable default account checks" );
if( "yes" >< disable_da )
  set_kb_item( name:"default_credentials/disable_default_account_checks", value:TRUE );

credentials_list = script_get_preference_file_content( "Credentials file:" );
if( ! credentials_list )
  exit( 0 );

credentials_lines = split( credentials_list, keep:FALSE );

foreach line( credentials_lines ) {
  # nb: ';' was used pre r9566 but was changed to ':' as a separator as the
  # GSA is stripping ';' from the NVT description. Keeping both in here
  # for backwards compatibility with older scan configs.
  if( line !~ "^.+;.+$" && line !~ "^.+:.+$" ) {
    log_message( port:0, data:"Invalid line " + line + " in uploaded credentials file. Scanner will not use this line." );
    continue;
  }
  # nb: Make sure to have the same syntax / fields like in default_credentials.inc
  # The "all" is used in default_ssh_credentials.nasl and default_http_auth_credentials.nasl
  # to decide if the credential should be used.
  set_kb_item( name:"default_credentials/credentials", value:line + ":custom:all" );
}

uploaded_credentials_only = script_get_preference( "Use only credentials listed in uploaded file:" );
set_kb_item( name:"default_credentials/uploaded_credentials_only", value:uploaded_credentials_only );

exit( 0 );