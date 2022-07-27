###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siemens_desigo_bacnet_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Siemens Desigo PXC Detection (BACNET)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140728");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-26 11:48:03 +0700 (Fri, 26 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens Desigo PXC Detection (BACNET)");

  script_tag(name:"summary", value:"Detection of Siemens Desigo PXC

Tries to detect Siemens Desigo PXC over the BACnet protocol.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_bacnet_detect.nasl");
  script_mandatory_keys("bacnet/vendor", "bacnet/model_name");

  script_xref(name:"URL", value:"https://www.siemens.com/global/en/home/products/buildings/automation/desigo.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

vendor = get_kb_item("bacnet/vendor");
if (!vendor || "Siemens Building Technologies" >!< vendor)
  exit(0);

model = get_kb_item("bacnet/model_name");
if (!model || model !~ "^(PXC|PX MMI)")
  exit(0);

set_kb_item(name: "siemens_desigo_pxc/model", value: model);

fw_version = "unknown";

fw = get_kb_item("bacnet/firmware");
if (fw) {
  fw_tmp = eregmatch(pattern: "FW(Id)?=V([0-9.]+)", string: fw);
  if (!isnull(fw_tmp[2])) {
    fw_version = fw_tmp[2];
    set_kb_item(name: "siemens_desigo_pxc/fw_version", value: fw_version);
  }

  hw = eregmatch(pattern: "HW=V([0-9.]+)", string: fw);
  if (!isnull(hw[1])) {
    hw_version = hw[1];
    set_kb_item(name: "siemens_desigo_pxc/hw_version", value: hw_version);
    extra = "Hardware version:  " + hw_version;
  }
  else {
    hw = eregmatch(pattern: "HW=V([0-9.]+)", string: model);
    if (!isnull(hw[1])) {
      hw_version = hw[1];
      set_kb_item(name: "siemens_desigo_pxc/hw_version", value: hw_version);
      extra = "Hardware version:  " + hw_version;
    }
  }
}

set_kb_item(name: "siemens_desigo_pxc/installed", value: TRUE);

cpe = build_cpe(value: fw_version, exp: "^([0-9.]+)", base: "cpe:/a:siemens:desigo_pxc:");
if (!cpe)
  cpe = 'cpe:/a:siemens:desigo_pxc';

register_product(cpe: cpe, port: 47808, service: "bacnet", proto: "udp");

log_message(data: build_detection_report(app: "Siemens Desigo PCX " + model, version: fw_version,
                                         install: "47808/udp", cpe: cpe, concluded: fw, extra: extra),
            port: 47808, proto: "udp");

exit(0);
