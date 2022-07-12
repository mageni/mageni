##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_etcd_auth_vuln.nasl 13721 2019-02-18 07:47:09Z asteins $
#
# etcd Authentication Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:coreos:etcd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141874");
  script_version("$Revision: 13721 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 08:47:09 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-15 10:13:42 +0700 (Tue, 15 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-16886");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("etcd Authentication Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_etcd_detect.nasl");
  script_mandatory_keys("etcd/installed");

  script_tag(name:"summary", value:"etcd is vulnerable to an improper authentication issue when role-based access
control (RBAC) is used and client-cert-auth is enabled.");

  script_tag(name:"insight", value:"If an etcd client server TLS certificate contains a Common Name (CN) which
matches a valid RBAC username, a remote attacker may authenticate as that user with any valid (trusted) client
certificate in a REST API request to the gRPC-gateway.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"etcd version 3.2.x and 3.3.x.");

  script_tag(name:"solution", value:"Update to version 3.2.26, 3.3.11 or later.");

  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/pull/10366");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/blob/1eee465a43720d713bb69f7b7f5e120135fdb1ac/CHANGELOG-3.2.md#security-authentication");
  script_xref(name:"URL", value:"https://github.com/etcd-io/etcd/blob/1eee465a43720d713bb69f7b7f5e120135fdb1ac/CHANGELOG-3.3.md#security-authentication");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.2", test_version2: "3.2.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.26");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.3", test_version2: "3.3.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.11");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
