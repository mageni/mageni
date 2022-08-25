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

CPE = "cpe:/a:openwrt:openwrt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148622");
  script_version("2022-08-23T10:11:31+0000");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-23 05:33:30 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-11 15:29:00 +0000 (Thu, 11 Feb 2021)");

  script_cve_id("CVE-2021-22161");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenWRT < 19.07.7 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openwrt_ssh_login_detect.nasl");
  script_mandatory_keys("openwrt/detected");

  script_tag(name:"summary", value:"OpenWRT is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In case a link prefix route points to a point-to-point link it
  can trigger a routing loop if the destination IPv6 address belongs to the prefix and is not a
  local IPv6 address. If such a packet is received and not directed to a local IPv6 address it will
  be routed back to the point-to-point link due to the link prefix route, the upstream ISP router
  will in its turn route the IPv6 packet back due to the assigned prefix route creating a 'ping
  pong' effect.

  The possible routing loop on point-to-point links (e.g PPP) can happen when router advertisements
  are received having at least one global unique IPv6 prefix for which the on-link flag is set. The
  WAN interface is assigned the global unique prefix (e.g. 2001:db8:1:0::/64) from which an IPv6
  address is picked which will be installed on the wan interface
  (e.g. 2001:db8:1:0:5054:ff:feab:d87c/64).

  As the on-link flag is set the prefix route 2001:db8:1::/64 will be present in the routing table
  which will route any packet with as destination 2001:db8:1::/64 to the WAN interface and will be
  routed back by the upstream router due to the WAN interface having been assigned the global
  unique prefix. Besides not installing the prefix route 2001:db8:1::/64 on point-to-point links
  adding an unreachable route is required to avoid the routing loop.");

  script_tag(name:"affected", value:"OpenWRT version 19.07.6 and prior.");

  script_tag(name:"solution", value:"Update to version 19.07.7 or later.");

  script_xref(name:"URL", value:"https://openwrt.org/advisory/2021-02-02-1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "19.07.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.07.7");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
