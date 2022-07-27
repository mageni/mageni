###############################################################################
# OpenVAS Vulnerability Test
# $Id: xedus_detect.nasl 13685 2019-02-15 10:06:52Z cfischer $
#
# Xedus detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

# Ref: James Bercegay of the GulfTech Security Research Team

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14644");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  #  script_bugtraq_id(11071);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Xedus detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Peer-To-Peer File Sharing");
  # nb: Don't add a dependency to http_version.nasl or gb_get_http_banner.nasl to avoid cyclic dependency to embedded_web_server_detect.nasl
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 4274);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host runs Xedus Peer to Peer webserver, it provides
  the ability to share files, music, and any other media, as well as create robust and dynamic web sites,
  which can feature database access, file system access, with full .net support.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

exit(0); # FP-prone # TODO: Fix the detection if possible...

port = get_http_port( default:4274 );

url = "/testgetrequest.x?param='free%20nvttest'";
req = http_get( item:url, port:port );
rep = http_keepalive_send_recv( port:port, data:req );

if( egrep( pattern:"free nvttest", string:rep ) ) {
  set_kb_item( name:"xedus/running", value:TRUE );
  set_kb_item( name:"xedus/" + port + "/running", value:TRUE );
  http_set_is_marked_embedded( port:port );
  log_message( port:port );
}

exit( 0 );