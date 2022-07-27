###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_algosec_detect.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# AlgoSec Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140787");
  script_version("$Revision: 10908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-20 12:32:03 +0700 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AlgoSec Detection");

  script_tag(name:"summary", value:"Detection of AlgoSec Security Management Solution.

The script sends a connection request to the server and attempts to detect AlgoSec and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.algosec.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/algosec/suite/login.html");

if ("algosec.ico" >< res && "Security Management Suite" >< res && "Configuring..." >< res) {
  version = "unknown";

  url = '/algosec/data/status.php';
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # Appliance Version: v2017.2.0-b55
  # Appliance Version: v6.11-b30
  vers = eregmatch(pattern: "Appliance Version: v([0-9a-z.-]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  # Firewall Analyzer version
  # AFA Version: v2017.2.390-b81
  # AFA Version: v6.11.0-b744
  afa_vers = eregmatch(pattern: "AFA Version: v([0-9a-z.-]+)", string: res);
  if (!isnull(afa_vers[1])) {
    afa_version = afa_vers[1];
    extra = 'Firewall Analyzer version: ' + afa_version + '\n';
    set_kb_item(name: "algosec/afa_version", value: afa_version);
  }

  # FireFlow version
  # v2017.2.390-b81
  # v6.11.0-b744
  ff_vers = eregmatch(pattern: "FireFlow Version: [^v]+v([0-9a-z.-]+)", string: res);
  if (!isnull(ff_vers[1])) {
    ff_version = ff_vers[1];
    extra += 'FireFlow version:          ' + ff_version + '\n';
    set_kb_item(name: "algosec/ff_version", value: ff_version);
  }

  # BusinessFlow version
  # BusinessFlow Version: v2017.2.390-b8
  # BusinessFlow Version: v6.11.0-b744
  bf_vers = eregmatch(pattern: "BusinessFlow Version: v([0-9a-z.-]+)", string: res);
  if (!isnull(bf_vers[1])) {
    bf_version = bf_vers[1];
    extra += 'BusninessFlow version:     ' + bf_version + '\n';
    set_kb_item(name: "algosec/bf_version", value: bf_version);
  }

  # MAC
  mac = eregmatch(pattern: "Appliance MAC address: ([A-F0-9:]{17})", string: res);
  if (!isnull(mac[1])) {
    extra += 'Mac Address:               ' + mac[1] + '\n';
    register_host_detail(name: "MAC", value: mac[1], desc: "gb_algosec_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac[1]);
  }

  set_kb_item(name: "algosec/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9a-z.-]+)", base: "cpe:/a:algosec:algosec:");
  if (!cpe)
    cpe = 'cpe:/a:algosec:algosec';

  register_product(cpe: cpe, location: "/algosec", port: port);

  log_message(data: build_detection_report(app: "AlgoSec", version: version, install: "/algosec", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
