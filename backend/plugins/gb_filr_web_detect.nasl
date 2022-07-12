###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_filr_web_detect.nasl 13825 2019-02-22 06:38:47Z ckuersteiner $
#
# Filr Web Interface Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105826");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13825 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-22 07:38:47 +0100 (Fri, 22 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-07-25 16:16:12 +0200 (Mon, 25 Jul 2016)");

  script_name("Filr Web Interface Detection");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Filr Web Interface");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:8443 );

url = '/ssf/a/do?p_name=ss_forum&p_action=1&action=__login';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "<title>(Novell|Micro Focus) Filr</title>" )
{
  cpe = 'cpe:/a:microfocus:filr';
  set_kb_item( name:'filr/webinterface/detected', value:port );

  register_product( cpe:cpe, location:"/", port:port, service:'www' );
  log_message( port:port, data: 'The Filr Web Interface is running at this port.\nCPE: ' + cpe);
  exit( 0 );
}

exit( 0 );
