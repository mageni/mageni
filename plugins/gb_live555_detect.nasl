###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_live555_detect.nasl 14169 2019-03-14 09:23:14Z jschulte $
#
# LIVE555 Streaming Media Server Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107180");
  script_version("$Revision: 14169 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 10:23:14 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-05-22 12:42:40 +0200 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("LIVE555 Streaming Media Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 8554);

  script_tag(name:"summary", value:"Detection of the installed version of LIVE555 Streaming Media Server.

  The script detects the version of LIVE555 Streaming Media Server on the remote host via RSTP banner,
  to extract the version number and to set the KB entries.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:live555:streaming_media:";

include( "http_func.inc" );
include( "misc_func.inc" );
include( "cpe.inc" );
include( "host_details.inc" );

port = get_port_for_service( proto: "rtsp", default: 8854 );

#nb: HTTP GET against RTSP port request may deliver the Server Banner
#    even if RTSP fails to do so
if (!banner = get_kb_item("RTSP/" + port + "/Server"))
  if(!banner = get_kb_item("www/banner/" + port))
    exit( 0 );

if ("LIVE555 Streaming Media" >< banner ) {

  version = "unknown";
  Ver = eregmatch(pattern: "LIVE555 Streaming Media v([0-9.]+)", string: banner);
  if (!isnull(Ver[1])) {
    version = Ver[1];
    set_kb_item(name: "live555_streaming_media/ver", value: version);
  }
  set_kb_item( name:"live555_streaming_media/installed", value:TRUE );

  register_and_report_cpe(app:"LIVE555 Streaming media",
                          ver: version,
                          concluded: Ver[0],
                          base: CPE,
                          expr: '([0-9.]+)',
                          insloc: port + '/rtsp',
                          regPort: port,
                          regService: 'RTSP');
}

exit( 0 );
