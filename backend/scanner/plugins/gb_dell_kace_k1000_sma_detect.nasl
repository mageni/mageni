###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_k1000_sma_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# Dell KACE K1000 Systems Management Appliance (SMA) Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803734");
  script_version("$Revision: 10915 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-08-12 19:47:34 +0530 (Mon, 12 Aug 2013)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dell KACE K1000 Systems Management Appliance (SMA) Detection");

  script_tag(name:"summary", value:"Detection of Dell KACE K1000 Systems Management Appliance.

The script sends a connection request to the server and attempts to extract the version number from the reply.

This NVT has been replaced by NVT 'Quest KACE Systems Management Applicance (SMA) Detection'
(OID: 1.3.6.1.4.1.25623.1.0.141135).");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");

  script_require_ports("Services/www", 80);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("KACE-Appliance/banner");

  script_tag(name:"deprecated", value: TRUE);

  exit(0);
}

exit(66);

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");


port = get_http_port(default:80);

banner = get_http_banner(port: port);

if("X-DellKACE-Appliance: k1000" >< banner)
{
  version = "unknown";

  vers = eregmatch(string: banner, pattern: "X-DellKACE-Version: ([0-9.]+)");
  if(!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "kace_1000/version", value: version);
  }

  set_kb_item(name: "kace_1000/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dell:kace_k1000_systems_management_appliance:");
  if(!cpe)
    cpe = 'cpe:/a:dell:kace_k1000_systems_management_appliance';

  register_product(cpe: cpe, location: '/', port: port);

  log_message(data: build_detection_report(app: "Dell KACE K1000",version: version, install: '/', cpe: cpe,
                                           concluded: vers[0]),
              port:port);
  exit(0);
}

exit(0);
