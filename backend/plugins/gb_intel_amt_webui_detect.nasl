###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intel_amt_webui_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Intel Active Management Technology WebUI interface Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105337");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-28 16:12:01 +0200 (Fri, 28 Aug 2015)");
  script_name("Intel Active Management Technology WebUI interface Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract the version number
from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 16992, 16993);
  script_mandatory_keys("IAMT/banner");

  exit(0);
}


include("http_func.inc");

include("host_details.inc");

port = get_http_port( default:16992 );
banner = get_http_banner( port:port );

if( "Server: Intel(R) Active Management Technology" >!< banner ) exit( 0 );

set_kb_item(name:"intel_amt/installed",value:TRUE);

vers = 'unknown';
cpe = 'cpe:/h:intel:active_management_technology';

version = eregmatch( pattern:'Server: Intel\\(R\\) Active Management Technology ([0-9.]+)', string:banner );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:"/", port:port );

log_message( data: build_detection_report( app:"Intel Active Management Technology",
                                           version:vers,
                                           install:"/",
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:port );



exit(0);

