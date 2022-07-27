##############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_authorization.nasl 13981 2019-03-04 14:49:43Z cfischer $
#
# Set information for smb authorization in KB.
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
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
##############################################################################

# The two entries "SMB/dont_send_ntlmv1" and "SMB/dont_send_in_cleartext"
# are not handled here yet. They are still managed in logins.nasl.

# Unlike the old code in logins.nasl, here only a single set of
# credentials is managed. Thus the strange name used for the KB.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90023");
  script_version("$Revision: 13981 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 15:49:43 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-06-02 00:42:27 +0200 (Mon, 02 Jun 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SMB Authorization"); # nb: Don't change the script name, this name is hardcoded within some manager functions...
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Credentials");

  # Don't change the preference names, those names are hardcoded within some manager functions...
  # nb: Same goes for id: parameter, those numbers are hardcoded in the manager as well.
  script_add_preference(name:"SMB login:", type:"entry", value:"", id:1);
  script_add_preference(name:"SMB password:", type:"password", value:"", id:2);
  script_add_preference(name:"SMB domain (optional):", type:"entry", value:"", id:3);

  script_tag(name:"summary", value:"This script allows users to enter the information
  required to authorize and login via SMB.

  These data are used by tests that require authentication.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

smb_login    = script_get_preference( "SMB login:", id:1 );
smb_password = script_get_preference( "SMB password:", id:2 );
smb_domain   = script_get_preference( "SMB domain (optional):", id:3 );

if( smb_login )    set_kb_item( name:"SMB/login_filled/0", value:smb_login );
if( smb_password ) set_kb_item( name:"SMB/password_filled/0", value:smb_password );
if( smb_domain )   set_kb_item( name:"SMB/domain_filled/0", value:smb_domain );

exit( 0 );