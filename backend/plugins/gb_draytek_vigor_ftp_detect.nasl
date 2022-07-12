# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108749");
  script_version("2020-04-17T10:07:38+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-20 08:28:46 +0000 (Mon, 20 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-17 07:43:42 +0000 (Fri, 17 Apr 2020)");
  script_name("DrayTek Vigor Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/draytek/detected");

  script_tag(name:"summary", value:"Detection of DrayTek Vigor devices via FTP.

  The script attempts to identify a DrayTek Vigor device via a FTP banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );

if( ! banner || "220 DrayTek FTP" >!< banner )
  exit( 0 );

version = "unknown";

set_kb_item( name:"draytek/vigor/detected", value:TRUE );
set_kb_item( name:"draytek/vigor/ftp/detected", value:TRUE );
set_kb_item( name:"draytek/vigor/ftp/port", value:port );
set_kb_item( name:"draytek/vigor/ftp/" + port + "/concluded", value:banner );
set_kb_item( name:"draytek/vigor/ftp/" + port + "/version", value:version );

exit( 0 );
