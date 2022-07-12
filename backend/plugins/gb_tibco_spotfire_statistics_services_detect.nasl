###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tibco_spotfire_statistics_services_detect.nasl 13034 2019-01-11 09:35:23Z ckuersteiner $
#
# TIBCO Spotfire Statistics Services Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141868");
  script_version("$Revision: 13034 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-11 10:35:23 +0100 (Fri, 11 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-11 14:27:25 +0700 (Fri, 11 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TIBCO Spotfire Statistics Services Detection");

  script_tag(name:"summary", value:"Detection of TIBCO Spotfire Statistics Services.

The script sends a connection request to the server and attempts to detect TIBCO Spotfire Statistics Services and
to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("HttpServer/banner");
  script_require_ports("Services/www", 8080, 443);

  script_xref(name:"URL", value:"https://www.tibco.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

banner = get_http_banner(port: port);
if ("Server: HttpServer" >!< banner)
  exit(0);

res = http_get_cache(port: port, item: "/");

# We should get a '302 Foud' since the service name is set by the admin
if (res !~ "^HTTP/1\.[01] 302" || "Location: " >!< res)
  exit(0);

dir = eregmatch(pattern: 'Location: (http(s)?://[^/]+)?(/[^\r\n]+)', string: res);
if (isnull(dir[3]))
  exit(0);

dir = dir[3];

res = http_get_cache(port: port, item: dir + "/");

if ("Welcome to TIBCO Spotfire Statistics Services" >< res && 'alt="TIBCO Spotfire Statistics Services"' >< res) {
  version = "unknown";

  # Don't use the eg. Version 9.11.0 (V13), this seems to be not the SSS version
  # instead use the release notes link
  # eg. <td><a href="https://docs.tibco.com/go/sf_statsvcs/7.11.1/TIB_sf_statsvcs_7.11.1_relnotes.pdf"
  vers = eregmatch(pattern: "sf_statsvcs/([0-9.]+)/", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "tibco/spotfire_statistics_services/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:tibco:spotfire_statistics_services:");
  if (!cpe)
    cpe = 'cpe:/a:tibco:spotfire_statistics_services';

  register_product(cpe: cpe, location: dir, port: port, service: "www");

  log_message(data: build_detection_report(app: "TIBCO Spotfire Statistics Services", version: version,
                                           install: dir, cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
