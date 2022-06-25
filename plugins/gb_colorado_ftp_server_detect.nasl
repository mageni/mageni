###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_colorado_ftp_server_detect.nasl 13497 2019-02-06 10:45:54Z cfischer $
#
# ColoradoFTP Server Remote Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807878");
  script_version("$Revision: 13497 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 11:45:54 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-08-23 08:13:26 +0200 (Tue, 23 Aug 2016)");
  script_name("ColoradoFTP Server Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/coldcore/coloradoftp/detected");

  script_tag(name:"summary", value:"Detects the installed version of
  ColoradoFTP Server.

  The script sends a connection request to the server and attempts to
  extract the version from the reply");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);

if(banner && "Welcome to ColoradoFTP" >< banner && "www.coldcore.com" >< banner) {

  ftpVer = "unknown";
  set_kb_item(name:"ColoradoFTP/Server/installed", value:TRUE);
  set_kb_item(name:"ColoradoFTP/Server/Ver", value:ftpVer);

  cpe = "cpe:/a:colorado:coloradoftpserver";
  register_product(cpe:cpe, location:"/", port:ftpPort, service:"ftp");
  log_message(data:build_detection_report(app:"ColoradoFT Server",
                                           version:ftpVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:banner),
                                           port:ftpPort);
}

exit(0);