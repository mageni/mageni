###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_m_and_r_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# EMC M&R (Watch4net) Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105240");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-20 10:13:43 +0100 (Fri, 20 Mar 2015)");
  script_name("EMC M&R (Watch4net) Detection");

  script_tag(name:"summary", value:"The script sends a connection
request to the server and attempts to extract the version number
from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 58080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:58080 );

dirs = make_list("/APG","/centralized-management","/device-discovery");

foreach dir ( dirs )
{
  url = dir + '/info/about';
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf !~ "<title>About.*EMC M&(amp;)?R</title>" || "EMC Corporation" >!< buf ) exit( 0 );

  cpe = 'cpe:/a:emc:watch4net';
  vers = 'unknown';

  version = eregmatch( pattern:'EMC M&amp;R v([0-9.]+(u[0-9]+)?)( - ([0-9]+))?', string:buf );

  if( ! isnull( version[1] ) )
  {
    vers = version[1];
    report_vers = vers;
    cpe += ':' + vers;
  }

  set_kb_item(name:"emc_m_r/installed",value:TRUE);
  set_kb_item(name:"emc_m_r/version",value:vers);

  if( ! isnull( version[4] ) )
  {
    set_kb_item(name:"emc_m_r/build",value:version[4]);
    report_vers += ' (' + version[4] + ')';
  }

  register_product( cpe:cpe, location:dir, port:port );

  log_message( data: build_detection_report( app:"EMC M&R (Watch4net)",
                                             version:report_vers,
                                             install:dir,
                                             cpe:cpe,
                                             concluded: version[0] ),
               port:port );
  exit( 0 );

}

exit(0);

