# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.148615");
  script_version("2022-08-22T10:11:10+0000");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-19 04:43:41 +0000 (Fri, 19 Aug 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("OpenWRT Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/openwrt/detected");

  script_tag(name:"summary", value:"SSH login-based detection of OpenWRT.");

  script_xref(name:"URL", value:"https://openwrt.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("ssh/login/openwrt/detected"))
  exit(0);

if (!port = get_kb_item("ssh/login/openwrt/port"))
  exit(0);

version = "unknown";
location = "/";

# NAME="OpenWrt"
# VERSION="21.02.3"
# ID="openwrt"
# ID_LIKE="lede openwrt"
# PRETTY_NAME="OpenWrt 21.02.3"
# VERSION_ID="21.02.3"
# HOME_URL="https://openwrt.org/"
# BUG_URL="https://bugs.openwrt.org/"
# SUPPORT_URL="https://forum.openwrt.org/"
# BUILD_ID="r16554-1d4dea6d4f"
# OPENWRT_BOARD="x86/64"
# OPENWRT_ARCH="x86_64"
# OPENWRT_TAINTS=""
# OPENWRT_DEVICE_MANUFACTURER="OpenWrt"
# OPENWRT_DEVICE_MANUFACTURER_URL="https://openwrt.org/"
# OPENWRT_DEVICE_PRODUCT="Generic"
# OPENWRT_DEVICE_REVISION="v0"
# OPENWRT_RELEASE="OpenWrt 21.02.3 r16554-1d4dea6d4f"
if (rls = get_kb_item("ssh/login/openwrt/" + port + "/etc_os-release")) {
  vers = eregmatch(pattern: 'VERSION\\s*=\\s*"([0-9.]+)"', string: rls);
  if (!isnull(vers[1]))
    version = vers[1];

  concl_loc = "/etc/os-release";
}

set_kb_item(name: "openwrt/detected", value: TRUE);
set_kb_item(name: "openwrt/ssh-login/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openwrt:openwrt:");
if (!cpe)
  cpe = "cpe:/a:openwrt:openwrt";

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "OpenWRT Detection (SSH Login)",
                       runs_key: "unixoide");

register_product(cpe: cpe, location: location, port: port, service: "ssh-login");

log_message(data: build_detection_report(app: "OpenWRT", version: version, install: location, cpe: cpe,
                                         concluded: "'" + vers[0] + "' from file '" + concl_loc + "'"),
            port: port);

exit(0);
