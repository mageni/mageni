###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vibnode_ftp_detect.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# PRUFTECHNIK VIBNODE Detection (FTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108340");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-02-16 10:43:37 +0100 (Fri, 16 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PRUFTECHNIK VIBNODE Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/prueftechnik/vibnode/detected");

  script_tag(name:"summary", value:"The script sends a FTP connection request to the remote
  host and attempts to detect the presence of a PRUFTECHNIK VIBNODE device and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );

# 220 Welcome to VibNode.  (1.15  VN-070926-b02)  Ready for user login.
# 220 Welcome to VIBNODE.  (VN-3.6.0-131108-b11 / OS_1.15)  Ready for user login.
if( banner && "welcome to vibnode." >< tolower( banner ) ) {

  app_version = "unknown";
  os_version  = "unknown";
  set_kb_item( name:"vibnode/detected", value:TRUE );
  set_kb_item( name:"vibnode/ftp/detected", value:TRUE );
  set_kb_item( name:"vibnode/ftp/port", value:port );

  app_vers = eregmatch( pattern:"Welcome to VIBNODE\..*\(VN-([0-9.]+)", string:banner );
  if( ! isnull( app_vers[1] ) ) app_version = app_vers[1];

  os_vers = eregmatch( pattern:"Welcome to VIBNODE\..*( \(| / OS_)([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( os_vers[2] ) ) os_version = os_vers[2];

  set_kb_item( name:"vibnode/ftp/" + port + "/concluded", value:banner );
  set_kb_item( name:"vibnode/ftp/" + port + "/app_version", value:app_version );
  set_kb_item( name:"vibnode/ftp/" + port + "/os_version", value:os_version );
}

exit( 0 );