###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_pagespeed_modules_detect.nasl 10898 2018-08-10 13:38:13Z cfischer $
#
# PageSpeed Modules (mod_pagespeed/ngx_pagespeed) Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111099");
  script_version("$Revision: 10898 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:38:13 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-05-03 17:00:00 +0200 (Tue, 03 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PageSpeed Modules (mod_pagespeed/ngx_pagespeed) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify the
  PageSpeed Modules (mod_pagespeed/ngx_pagespeed) from the server banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

if( "x-mod-pagespeed" >< tolower( banner ) ) {

  version = "unknown";

  set_kb_item( name:"mod_pagespeed/installed", value:TRUE );

  ver = eregmatch( string:banner, pattern:"X-Mod-Pagespeed: ([0-9.\-]+)", icase:TRUE );
  if( ver[1] ) version = ver[1];

  cpe = build_cpe( value: version, exp:"^([0-9.\-]+)", base:"cpe:/a:google:mod_pagespeed:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:google:mod_pagespeed';

  register_product( cpe:cpe, location:port + '/tcp', port:port );

  log_message( data:build_detection_report( app:"mod_pagespeed",
                                            version:version,
                                            install:port + '/tcp',
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

if( "x-page-speed" >< tolower( banner ) ) {

  version = "unknown";

  set_kb_item( name:"ngx_pagespeed/installed", value:TRUE );

  ver = eregmatch( string:banner, pattern:"X-Page-Speed: ([0-9.\-]+)", icase:TRUE );
  if( ver[1] ) version = ver[1];

  cpe = build_cpe( value: version, exp:"^([0-9.\-]+)", base:"cpe:/a:google:ngx_pagespeed:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:google:ngx_pagespeed';

  register_product( cpe:cpe, location:port + '/tcp', port:port );

  log_message( data:build_detection_report( app:"ngx_pagespeed",
                                            version:version,
                                            install:port + '/tcp',
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );
