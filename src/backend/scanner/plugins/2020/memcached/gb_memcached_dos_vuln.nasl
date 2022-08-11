# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108730");
  script_version("2020-03-25T06:10:58+0000");
  script_tag(name:"last_modification", value:"2020-03-25 11:04:45 +0000 (Wed, 25 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-24 09:30:42 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2020-10931");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("memcached 1.6.x < 1.6.2 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_memcached_detect.nasl");
  script_mandatory_keys("Memcached/detected");

  script_tag(name:"summary", value:"memcached is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"The remote DoS (segfault) flaw exists in the code used to
  parse the binary protocol header that was introduced in 1.6.0.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Memcached versions 1.6.x prior to 1.6.2.");

  script_tag(name:"solution", value:"Update to version 1.6.2 or later.");

  script_xref(name:"URL", value:"https://github.com/memcached/memcached/issues/629");
  script_xref(name:"URL", value:"https://github.com/memcached/memcached/wiki/ReleaseNotes162");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto   = infos["proto"];

if (version_in_range(version: version, test_version: "1.6.0", test_version2: "1.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.2");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
