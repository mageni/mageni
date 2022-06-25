###############################################################################
# OpenVAS Vulnerability Test
# $Id: vnc_http.nasl 6695 2017-07-12 11:17:53Z cfischer $
#
# Check for VNC HTTP
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10758");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check for VNC HTTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
  script_family("Malware");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("vncviewer_jc/banner");
  script_require_ports("Services/www", 5800, 5801, 5802);

  script_tag(name:"solution", value:"Disable VNC access from the network by
  using a firewall, or stop VNC service if not needed.");

  script_tag(name:"summary", value:"The remote server is running VNC.
  VNC permits a console to be displayed remotely.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:5800 );

banner = get_http_banner(port:port);
if( ! banner ) exit( 0 );

if( "vncviewer.jar" >< banner || "vncviewer.class" >< banner ) {
  log_message( port:port );
  set_kb_item( name:"www/vnc", value:TRUE );
}

exit( 99 );