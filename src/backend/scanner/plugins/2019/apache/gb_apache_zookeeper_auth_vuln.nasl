# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:apache:zookeeper";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143178");
  script_version("2019-11-26T05:57:42+0000");
  script_tag(name:"last_modification", value:"2019-11-26 05:57:42 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-26 05:40:33 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-8012");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache ZooKeeper Quorum Peer Mutual Authentication Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apache_zookeeper_detect.nasl");
  script_mandatory_keys("apache/zookeeper/detected");

  script_tag(name:"summary", value:"Apache ZooKeeper is prone to a Quorum Peer mutual authentication
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"No authentication/authorization is enforced when a server attempts to join a
  quorum. As a result an arbitrary end point could join the cluster and begin propagating counterfeit changes to
  the leader.");

  script_tag(name:"affected", value:"Apache ZooKeeper prior to version 3.4.10 and version 3.5.0-alpha to
  3.5.3-beta.");

  script_tag(name:"solution", value:"Update to version 3.4.10, 3.5.4-beta or later.");

  script_xref(name:"URL", value:"https://zookeeper.apache.org/security.html#CVE-2018-8012");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.4.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.10");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.5.0", test_version2: "3.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.4-beta");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
