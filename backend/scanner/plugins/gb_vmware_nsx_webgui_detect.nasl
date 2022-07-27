###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_nsx_webgui_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Vmware NSX Web Management Interface Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105421");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-27 14:06:30 +0100 (Tue, 27 Oct 2015)");
  script_name("Vmware NSX Web Management Interface Detection");

  script_tag(name:"summary", value:"This script performs HTTP based detection of the Vmware NSX Webinterface");

  script_tag(name:"qod_type", value:"remote_active");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:443 );

url = '/login.jsp';
buf = http_get_cache( item:url, port:port );

if( "<title>VMware Appliance Management</title>" >!< buf || "VMW_NSX" >!< buf ) exit( 0 );

set_kb_item( name:"vmware_nsx/webui", value:TRUE );
set_kb_item( name:"vmware_nsx/webui/port", value:port );

log_message( data: 'Vmware NSX Web Management Interface is running at this port.\n', port:port );

exit(0);

