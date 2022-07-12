###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_cp_ftp_detect.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# Siemens SIMATIC CP Device Detection (FTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108345");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-02-20 09:28:27 +0100 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Siemens SIMATIC CP Device Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/siemens/simatic_cp/detected");

  script_tag(name:"summary", value:"This script performs FTP based detection of Siemens SIMATIC CP devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );

# CP 343-1 FTP-Server V2.00 ready for new user
# CP 343-1 IT FTP-Server V1.07 ready for new user
# CP 443-1 IT FTP-Server V1.07 ready for new user
if( banner && banner =~ "CP ([0-9\-]+) (IT )?FTP-Server V([0-9.]+) ready for new user" ) {

  model   = "unknown";
  version = "unknown";
  set_kb_item( name:"simatic_cp/detected", value:TRUE );
  set_kb_item( name:"simatic_cp/ftp/detected", value:TRUE );
  set_kb_item( name:"simatic_cp/ftp/port", value:port );

  mod = eregmatch( pattern:"CP ([0-9\-]+) (IT )?FTP-Server", string:banner );
  if( ! isnull( mod[1] ) ) model = mod[1];

  set_kb_item( name:"simatic_cp/ftp/" + port + "/concluded", value:banner );
  set_kb_item( name:"simatic_cp/ftp/" + port + "/model", value:model );
  set_kb_item( name:"simatic_cp/ftp/" + port + "/version", value:version );
}

exit( 0 );