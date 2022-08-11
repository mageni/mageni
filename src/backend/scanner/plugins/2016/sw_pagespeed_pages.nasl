###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_pagespeed_pages.nasl 5505 2017-03-07 10:00:18Z teissa $
#
# PageSpeed Modules (mod_pagespeed/ngx_pagespeed) Admin Pages accessible
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
  script_oid("1.3.6.1.4.1.25623.1.0.111076");
  script_version("$Revision: 5505 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-07 11:00:18 +0100 (Tue, 07 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-16 16:00:00 +0100 (Sat, 16 Jan 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("PageSpeed Modules (mod_pagespeed/ngx_pagespeed) Admin Pages accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify Admin Pages of the
  PageSpeed Modules (mod_pagespeed/ngx_pagespeed)");
  script_tag(name:"vuldetect", value:"Check the response if Admin Pages are enabled.");
  script_tag(name:"impact", value:"Based on the information shown an attacker might be able to gather additional info about
  the structure of the system and its applications.");
  script_tag(name:"affected", value:"Webservers with a PageSpeed Module (mod_pagespeed/ngx_pagespeed) loaded and
  missing restrictions to the Admin Pages.");
  script_tag(name:"solution", value:"Restrict access to the Admin Pages for authorized systems only.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

adminPages = make_list( "/ngx_pagespeed_statistics",
                        "/ngx_pagespeed_global_statistics",
                        "/ngx_pagespeed_message",
                        "/mod_pagespeed_statistics",
                        "/mod_pagespeed_global_statistics",
                        "/mod_pagespeed_message",
                        "/pagespeed_console",
                        "/pagespeed_admin/",
                        "/pagespeed_global_admin/" );

report = 'The following Admin pages were identified:\n';

port = get_http_port( default:80 );

foreach url( adminPages ) {

  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  if( "<b>Pagespeed Admin</b>" >< buf ) {
    report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
    found = TRUE;
  }
}

if( found ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
