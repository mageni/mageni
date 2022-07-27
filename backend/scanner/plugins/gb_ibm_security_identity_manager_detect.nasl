###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_security_identity_manager_detect.nasl 13070 2019-01-15 04:50:25Z ckuersteiner $
#
# IBM Security Identity Manager Detection
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.813523");
  script_version("$Revision: 13070 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-15 05:50:25 +0100 (Tue, 15 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-06-12 17:05:24 +0530 (Tue, 12 Jun 2018)");

  script_name("IBM Security Identity Manager Detection");

  script_tag(name:"summary", value:"Detection of IBM Security Identity Manager.

The script sends a connection request to the server and attempts to detect IBM Security Identity Manager and to
extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443, 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default: 443);

res = http_get_cache(item: "/itim/self/jsp/logon/login.jsp", port: port);

if ("IBM Security Identity Manager" >< res) {
  version = 'unknown';

  # IBM Security Identity Manager v7.0.1.7
  vers = eregmatch(pattern: 'IBM Security Identity Manager v([0-9.]+)', string: res);

  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "ibm/security_identity_manager/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([.0-9.]+)", base: "cpe:/a:ibm:security_identity_manager:");
  if (!cpe)
    cpe = "cpe:/a:ibm:security_identity_manager";

  register_product(cpe: cpe, location: '/', port: port, service: "www");

  log_message(data: build_detection_report(app: "IBM Security Identity Manager", version: version, install: '/',
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
