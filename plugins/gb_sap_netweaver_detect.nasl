###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_netweaver_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# SAP NetWeaver Application Server Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105302");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-22 11:54:01 +0200 (Mon, 22 Jun 2015)");
  script_name("SAP NetWeaver Application Server Detection");

  script_tag(name:"summary", value:"The script sends a connection
request to the server and attempts to extract the version number
from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:443 );

req = http_get(item: "/irj/portal", port: port);
buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if ("TITLE>SAP NetWeaver Application Server" >!< buf && "server: SAP NetWeaver Application Server" >!< buf && ("<title>Application Server Error" >!< buf && "SAP AG" >!< buf && "<title>SAP&#x20;NetWeaver&#x20;Portal</title>" >!< buf))

  exit(0);

version = 'unknown';

# /com.sap.portal.design.portaldesigndata/themes/portal/sap_tradeshow_plus/prtl_std/prtl_std_nn7.css?v=7.31.6.0.0" />
vers = eregmatch(pattern: 'com.sap.portal.design.portaldesigndata/themes/portal/.*v=([0-9.]+).*/>', string: buf);

#add check for new sap netweaver versions.
if (isnull(vers)) vers = eregmatch(pattern: 'com.sap.portal.theming.webdav.themeswebdavlistener/Portal/.*v=([0-9.]+).*/>', string: buf);

if (! isnull(vers)) {
  version = vers[1];
}

# Even though it might be tempting to use the server-banner for version detection => DON'T.
# The definitions of the versions in that banner are inconclusive and don't supply accurate results
# Maybe in the future SAP will release a list of what the numbers mean, but until then, the server banner is not a reliable source for the version number

set_kb_item(name: "sap_netweaver/version", value: version);
set_kb_item(name: "sap_netweaver/installed", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:sap:netweaver:");
if (!cpe)
  cpe = 'cpe:/a:sap:netweaver';

register_product( cpe:cpe, location:"/", port:port );

log_message(data: build_detection_report(app:"SAP NetWeaver Application Server",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded: vers[0]),
            port:port );

exit( 0 );
