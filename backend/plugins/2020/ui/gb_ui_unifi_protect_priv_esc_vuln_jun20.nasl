# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.144232");
  script_version("2020-07-14T09:17:17+0000");
  script_tag(name:"last_modification", value:"2020-07-14 09:17:17 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-14 08:47:29 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2020-8188");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("UniFi Protect < 1.13.3 1.14.0 < 1.14.10 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ubnt_discovery_protocol_detect.nasl");
  script_mandatory_keys("ubnt_discovery_proto/firmware");

  script_tag(name:"summary", value:"UniFi Protect is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"View only users can run certain custom commands which allows them to assign
  themselves unauthorized roles and escalate their privileges.");

  script_tag(name:"affected", value:"UniFi Protect version 1.13.2 and prior and 1.14.9 and prior.");

  script_tag(name:"solution", value:"Update to version 1.13.3, 1.14.10 or later.");

  script_xref(name:"URL", value:"https://community.ui.com/releases/Security-advisory-bulletin-012-012/1bba9134-f888-4010-81c0-b0dd53b9bda4");

  exit(0);
}

include("misc_func.inc");
include("version_func.inc");

if (!port = get_port_for_service(default: 10001, ipproto: "udp", proto: "ubnt_discovery"))
  exit(0);

if (!fw = get_kb_item("ubnt_discovery_proto/firmware"))
  exit(0);

# unifi-protect.arm64.v1.13.2.0.0.0
if (fw !~ "^unifi-protect")
  exit(0);

version = eregmatch(pattern: "unifi-protect\.[^.]+\.v([0-9.]+)", string: fw);
if (isnull(version[1]))
  exit(0);

if (version_is_less(version: version[1], test_version: "1.13.3")) {
  report = report_fixed_ver(installed_version: version[1], fixed_version: "1.13.3");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_in_range(version: version[1], test_version: "1.14", test_version2: "1.14.9")) {
  report = report_fixed_ver(installed_version: version[1], fixed_version: "1.14.10");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
