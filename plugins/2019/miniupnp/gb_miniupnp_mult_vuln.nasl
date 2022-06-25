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

CPE = "cpe:/a:miniupnp_project:miniupnpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142455");
  script_version("2019-05-22T09:11:13+0000");
  script_tag(name:"last_modification", value:"2019-05-22 09:11:13 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-22 09:00:07 +0000 (Wed, 22 May 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-12106", "CVE-2019-12107", "CVE-2019-12108", "CVE-2019-12109", "CVE-2019-12110",
                "CVE-2019-12111");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MiniUPnP <= 2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_miniupnp_detect_tcp.nasl");
  script_mandatory_keys("miniupnp/installed");

  script_tag(name:"summary", value:"MiniUPnP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MiniUPnP is prone to multiple vulnerabilities:

  - Use after free vulnerability (CVE-2019-12106)

  - Information disclosure vulnerability (CVE-2019-12107)

  - Multiple DoS vulnerabilities due to NULL pointer dereferences (CVE-2019-12108, CVE-2019-12109, CVE-2019-12110,
    CVE-2019-12111)");

  script_tag(name:"affected", value:"MiniUPnP version 2.1 and prior.");

  script_tag(name:"solution", value:"Apply the provided patches.");

  script_xref(name:"URL", value:"https://www.vdoo.com/blog/security-issues-discovered-in-miniupnp");
  script_xref(name:"URL", value:"https://github.com/miniupnp/miniupnp/commit/cd506a67e174a45c6a202eff182a712955ed6d6f");
  script_xref(name:"URL", value:"https://github.com/miniupnp/miniupnp/commit/bec6ccec63cadc95655721bc0e1dd49dac759d94");
  script_xref(name:"URL", value:"https://github.com/miniupnp/miniupnp/commit/13585f15c7f7dc28bbbba1661efb280d530d114c");
  script_xref(name:"URL", value:"https://github.com/miniupnp/miniupnp/commit/86030db849260dd8fb2ed975b9890aef1b62b692");
  script_xref(name:"URL", value:"https://github.com/miniupnp/miniupnp/commit/f321c2066b96d18afa5158dfa2d2873a2957ef38");
  script_xref(name:"URL", value:"https://github.com/miniupnp/miniupnp/commit/cb8a02af7a5677cf608e86d57ab04241cf34e24f");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less_equal(version: version, test_version: "2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply Patch");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
