###############################################################################
# OpenVAS Vulnerability Test
# $Id: plaxo_installed.nasl 10200 2018-06-14 14:39:20Z cfischer $
#
# Plaxo Client Is Installed
#
# Authors:
# Tom Ferris
#
# Copyright:
# Copyright (C) 2005 Tom Ferris <tommy@security-protocols.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# <tommy@security-protocols.com>
# 6/29/2005
# www.security-protocols.com

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18591");
  script_version("$Revision: 10200 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-14 16:39:20 +0200 (Thu, 14 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Plaxo Client Is Installed");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Tom Ferris <tommy@security-protocols.com>");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"The remote host has the Plaxo Client software installed. Plaxo is a contact manager.
  Make sure its use is compatible with your corporate security policy.");

  script_tag(name:"solution", value:"Uninstall this software if it does not match your security policy");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if( ! registry_key_exists( key:key ) ) exit( 0 );

foreach item( registry_enum_keys( key:key ) ) {
  name = registry_get_sz( key:key + item, item:"DisplayName" );
  if( "Plaxo" >< name ) {
    log_message( port:0 );
  }
}

exit( 0 );
