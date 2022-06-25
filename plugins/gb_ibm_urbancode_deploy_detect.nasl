###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_urbancode_deploy_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# IBM UrbanCode Deploy Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106562");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-03 09:38:09 +0700 (Fri, 03 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM UrbanCode Deploy Detection");

  script_tag(name:"summary", value:"Detection of IBM UrbanCode Deploy

The script sends a HTTP connection request to the server and attempts to detect the presence of IBM UrbanCode
Deploy and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www-03.ibm.com/software/products/en/ucdep");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ("<title>IBM UrbanCode Deploy: Log In</title>" >< res && 'productName">UrbanCode Deploy' >< res) {
  version = "unknown";

  vers = eregmatch(pattern: 'productVersion">([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "ibm_urbancode_deploy/version", value: version);
  }

  set_kb_item(name: "ibm_urbancode_deplay/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:urbancode_deploy:");
  if (!cpe)
    cpe = 'cpe:/a:ibm:urbancode_deploy';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "IBM UrbanCode Deploy", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
