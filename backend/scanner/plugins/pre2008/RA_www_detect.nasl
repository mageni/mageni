###############################################################################
# OpenVAS Vulnerability Test
# $Id: RA_www_detect.nasl 14336 2019-03-19 14:53:10Z mmartin $
#
# RemotelyAnywhere WWW detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Broken link deleted
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RemotelyAnywhere WWW detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Malware");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("RemotelyAnywhere/banner");
  script_require_ports("Services/www", 2000, 2001);

  script_tag(name:"summary", value:"The RemotelyAnywhere WWW server is running on this system.
  According to NAVCIRT attackers love this management tool.

  If you installed it, ignore this warning. If not, your machine is
  compromised by an attacker.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:2000 );

banner = get_http_banner( port:port );

if( ! banner || "RemotelyAnywhere" >!< banner ) exit( 0 );

# TBD: check default account administrator / remotelyanywhere
if( egrep( pattern:"^Server: *RemotelyAnywhere", string:banner ) ) {
  log_message( port:port );
  exit( 0 );
}

exit( 99 );
