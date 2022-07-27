###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_honeywell_xlweb_bacnet_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Honeywell XL Web Detection (BACNET)
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
  script_oid("1.3.6.1.4.1.25623.1.0.106560");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-03 09:38:09 +0700 (Fri, 03 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Honeywell XL Web Detection (BACNET)");

  script_tag(name:"summary", value:"Detection of Honeywell XL Web

Tries to detect Honeywell XL Web over the BACnet protocol.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_bacnet_detect.nasl");
  script_mandatory_keys("bacnet/vendor", "bacnet/model_name");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

vendor = get_kb_item("bacnet/vendor");
if (!vendor || "Honeywell" >!< vendor)
  exit(0);

mod = get_kb_item("bacnet/model_name");
if (!mod || "Excel Web" >!< mod)
  exit(0);

fw_version = "unknown";

fw = get_kb_item("bacnet/firmware");
if (fw) {
  fw = eregmatch(pattern: "XLWebExe-([0-9-]+)", string: fw);
  if (!isnull(fw[1])) {
    fw_version = ereg_replace(pattern: "-", string: fw[1], replace: ".");
    set_kb_item(name: "honeywell_xlweb/fw_version", value: fw_version);
  }
}

set_kb_item(name: "honeywell_xlweb/installed", value: TRUE);

cpe = build_cpe(value: fw_version, exp: "^([0-9.]+)", base: "cpe:/o:honeywell:excel_web_xl:");
if (!cpe)
  cpe = 'cpe:/o:honeywell:excel_web_xl';

register_product(cpe: cpe, port: 47808, service: "bacnet", proto: "udp");

log_message(data: build_detection_report(app: "Honeywell XL Web", version: fw_version, install: "47808/udp",
                                         cpe: cpe, concluded: fw),
            port: 47808, proto: "udp");

exit(0);
