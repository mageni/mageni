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

CPE = "cpe:/a:openldap:openldap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147062");
  script_version("2021-11-02T14:03:34+0000");
  script_tag(name:"last_modification", value:"2021-11-02 14:03:34 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-02 04:14:37 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_cve_id("CVE-2019-13057", "CVE-2019-13565");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenLDAP < 2.4.48 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openldap_consolidation.nasl");
  script_mandatory_keys("openldap/detected");

  script_tag(name:"summary", value:"OpenLDAP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-13057: When the server administrator delegates rootDN (database admin) privileges for
  certain databases but wants to maintain isolation (e.g., for multi-tenant deployments), slapd
  does not properly stop a rootDN from requesting authorization as an identity from another
  database during a SASL bind or with a proxyAuthz (RFC 4370) control. (It is not a common
  configuration to deploy a system where the server administrator and a DB administrator enjoy
  different levels of trust.)

  - CVE-2019-13565: When using SASL authentication and session encryption, and relying on the SASL
  security layers in slapd access controls, it is possible to obtain access that would otherwise be
  denied via a simple bind for any identity covered in those ACLs. After the first SASL bind is
  completed, the sasl_ssf value is retained for all new non-SASL connections. Depending on the ACL
  configuration, this can affect different types of operations (searches, modifications, etc.). In
  other words, a successful authorization step completed by one user affects the authorization
  requirement for a different user.");

  script_tag(name:"affected", value:"OpenLDAP prior to version 2.4.48.");

  script_tag(name:"solution", value:"Update to version 2.4.48 or later.");

  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9038");
  script_xref(name:"URL", value:"https://bugs.openldap.org/show_bug.cgi?id=9052");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.4.48")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.48", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
