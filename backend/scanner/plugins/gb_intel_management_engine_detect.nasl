###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intel_management_engine_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Intel Management Engine (ME) Firmware Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812220");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-22 12:31:00 +0530 (Wed, 22 Nov 2017)");
  script_name("Intel Management Engine (ME) Firmware Version Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the
 server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 16992);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");

include("host_details.inc");

imeport = get_http_port( default:16992 );

banner = get_http_banner( port:imeport );

if( "Server: Intel(R) Con. Management Engine" >!< banner ) exit( 0 );

set_kb_item(name:"intel_me/installed",value:TRUE);

vers = 'unknown';
cpe = 'cpe:/h:intel:management_engine';

version = eregmatch(pattern:'Server: Intel\\(R\\) Con. Management Engine ([0-9.]+)', string:banner);
if(version[1])
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:"/", port:imeport );


log_message( data: build_detection_report( app:"Intel Management Engine",
                                           version:vers,
                                           install:"/",
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:imeport );



exit(0);
