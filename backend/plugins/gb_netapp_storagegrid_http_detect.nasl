# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140337");
  script_version("2022-01-10T10:39:49+0000");
  script_tag(name:"last_modification", value:"2022-01-10 10:39:49 +0000 (Mon, 10 Jan 2022)");
  script_tag(name:"creation_date", value:"2017-08-30 16:31:32 +0700 (Wed, 30 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetApp StorageGRID Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of NetApp StorageGRID (formerly
  StorageGRID Webscale).");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("StorageGRID/banner");
  script_require_ports("Services/www", 443);

  script_xref(name:"URL", value:"http://www.netapp.com/us/products/data-management-software/object-storage-grid-sds.aspx");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port(default: 443);

banner = http_get_remote_headers(port: port);

# server: StorageGRID/11.5.0.4
# Server: StorageGRID/11.4.0.2
# Server: StorageGRID/11.3.0.12
if (concl = egrep(pattern: "^Server\s*:\s*StorageGRID", string: banner, icase: TRUE)) {

  concl = chomp(concl);
  version = "unknown";

  vers = eregmatch(pattern: "Server\s*:\s*StorageGRID/([0-9.]+)", string: concl, icase: TRUE);
  if (!isnull(vers[1])) {
    version = vers[1];
    concl = vers[0];
  }

  set_kb_item(name: "netapp/storagegrid/detected", value: TRUE);
  set_kb_item(name: "netapp/storagegrid/http/detected", value: TRUE);

  cpe1 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:netapp:storagegrid:");
  cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:netapp:storagegrid_webscale:");
  if (!cpe1) {
    cpe1 = "cpe:/a:netapp:storagegrid";
    cpe2 = "cpe:/a:netapp:storagegrid_webscale";
  }

  register_product(cpe: cpe1, location: "/", port: port, service: "www");
  register_product(cpe: cpe2, location: "/", port: port, service: "www");

  # Software seems to run on Debian, Ubuntu, CentOS and RHEL
  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: "HTTP banner",
                         desc: "NetApp StorageGRID Detection (HTTP)", runs_key: "unixoide");

  log_message(data: build_detection_report(app: "NetApp StorageGRID", version: version, install: "/",
                                           cpe: cpe1, concluded: concl),
              port: port);
  exit(0);
}

exit(0);
