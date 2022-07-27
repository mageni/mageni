###############################################################################
# OpenVAS Vulnerability Test
#
# RemotelyAnywhere Detection (HTTP)
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Broken link deleted
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.10920");
  script_version("2021-03-18T13:55:00+0000");
  script_tag(name:"last_modification", value:"2021-03-19 11:21:45 +0000 (Fri, 19 Mar 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("RemotelyAnywhere Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 2000);
  script_mandatory_keys("RemotelyAnywhere/banner");

  script_tag(name:"summary", value:"HTTP based detection of RemotelyAnywhere.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:2000 );

banner = http_get_remote_headers( port:port );

if( ! banner || "RemotelyAnywhere" >!< banner )
  exit( 0 );

# TBD: check default account administrator / remotelyanywhere
if( egrep( pattern:"^Server\s*:\s*RemotelyAnywhere", string:banner, icase:TRUE ) )
  log_message( port:port );

exit( 0 );
