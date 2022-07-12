###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_2000_web_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Dell KACE K2000 Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103317");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-11 10:17:05 +0100 (Fri, 11 Nov 2011)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Dell KACE K2000 Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("KACE-Appliance/banner");

  script_tag(name:"summary", value:"Detection of Dell KACE.

The script sends a connection request to the server and attempts to extract the version number from the reply.

This NVT has been replaced by NVT 'Quest KACE Systems Management Applicance (SMA) Detection'
(OID: 1.3.6.1.4.1.25623.1.0.141135).");

  script_xref(name:"URL", value:"http://www.kace.com/products/systems-deployment-appliance");

  script_tag(name:"deprecated", value: TRUE);

  exit(0);
}

exit(66);

include("http_func.inc");

include("host_details.inc");
include("cpe.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);

if (egrep(pattern: "X-KACE-Version:", string: banner, icase: TRUE)) {
  vers = "unknown";

  version = eregmatch(string: banner, pattern: "X-KACE-Version: ([0-9.]+)", icase:TRUE);
  if (!isnull(version[1])) {
    vers = version[1];
    set_kb_item(name: "kace_2000/version", value: vers);
  }

  cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/h:dell:kace_k2000_systems_deployment_appliance:");
  if(!cpe)
    cpe = 'cpe:/h:dell:kace_k2000_systems_deployment_appliance';

  set_kb_item(name: "kace_2000/detected", value: TRUE);

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Dell KACE K2000", version: vers, install: "/", cpe: cpe,
                                           concluded: version[0]),
              port: port);
  exit(0);
}

exit(0);
