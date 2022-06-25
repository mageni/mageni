###############################################################################
# OpenVAS Vulnerability Test
#
# Mercora IMRadio Detection
#
# Authors:
# Josh Zlatin-Amishav
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19585");
  script_version("2021-03-19T13:48:08+0000");
  script_tag(name:"last_modification", value:"2021-03-19 13:48:08 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Mercora IMRadio Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://www.mercora.com/default2.asp");

  script_tag(name:"summary", value:"SMB login-based detection of Mercora IMRadio.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if( ! registry_key_exists( key:key ) )
  exit( 0 );

foreach item( registry_enum_keys( key:key ) ) {
  name = registry_get_sz( key:key + item, item:"DisplayName" );
  if( "Mercora" >< name ) {
    log_message( port:0 );
  }
}

exit( 0 );