# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:coturn:coturn";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145204");
  script_version("2021-01-20T09:53:20+0000");
  script_tag(name:"last_modification", value:"2021-01-20 11:07:43 +0000 (Wed, 20 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-20 09:47:13 +0000 (Wed, 20 Jan 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2020-26262");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("coturn < 4.5.2 Loopback Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_coturn_http_detect.nasl");
  script_mandatory_keys("coturn/detected");

  script_tag(name:"summary", value:"coturn is prone to a loopback bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By default coturn does not allow peers to connect and relay packets to
  loopback addresses in the range of 127.x.x.x. However, it was observed that when sending a CONNECT request
  with the XOR-PEER-ADDRESS value of 0.0.0.0, a successful response was received and subsequently,
  CONNECTIONBIND also received a successful response. Coturn then is able to relay packets to the loopback
  interface.

  Additionally, when coturn is listening on IPv6, which is default, the loopback interface can also be reached
  by making use of either [::1] or [::] as the peer address.");

  script_tag(name:"impact", value:"By using the address 0.0.0.0 as the peer address, a malicious user will be
  able to relay packets to the loopback interface, unless --denied-peer-ip=0.0.0.0 (or similar) has been
  specified. Since the default configuration implies that loopback peers are not allowed, coturn
  administrators may choose to not set the denied-peer-ip setting.");

  script_tag(name:"affected", value:"coturn prior to version 4.5.2.");

  script_tag(name:"solution", value:"Update to version 4.5.2 or later.");

  script_xref(name:"URL", value:"https://github.com/coturn/coturn/security/advisories/GHSA-6g6j-r9rf-cm7p");
  script_xref(name:"URL", value:"https://www.rtcsec.com/post/2021/01/details-about-cve-2020-26262-bypass-of-coturns-default-access-control-protection");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "4.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
