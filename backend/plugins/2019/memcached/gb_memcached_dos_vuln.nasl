# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:memcached:memcached";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140211");
  script_version("2019-06-14T07:48:34+0000");
  script_tag(name:"last_modification", value:"2019-06-14 07:48:34 +0000 (Fri, 14 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-14 07:43:44 +0000 (Fri, 14 Jun 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-11596");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("memcached < 1.5.14 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_memcached_detect.nasl");
  script_mandatory_keys("Memcached/detected");

  script_tag(name:"summary", value:"memcached is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"A NULL pointer dereference was found in the 'lru mode' and 'lru temp_ttl'
  commands. This causes a denial of service when parsing crafted lru command messages in process_lru_command in
  memcached.c.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Memcached version prior to 1.5.14.");

  script_tag(name:"solution", value:"Update to version 1.5.14 or later.");

  script_xref(name:"URL", value:"https://github.com/memcached/memcached/issues/474");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version  = infos["version"];
proto    = infos["proto"];

if (version_is_less(version: version, test_version: "1.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.14");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
