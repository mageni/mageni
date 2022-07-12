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

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144824");
  script_version("2020-10-26T06:11:39+0000");
  script_tag(name:"last_modification", value:"2020-10-26 11:10:40 +0000 (Mon, 26 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-26 06:05:46 +0000 (Mon, 26 Oct 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2020-25829");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor < 4.1.18, 4.2.0 < 4.2.4, 4.3.0 < 4.3.4 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been found in PowerDNS Recursor where a remote attacker can cause
  the cached records for a given name to be updated to the 'Bogus' DNSSEC validation state, instead of their
  actual DNSSEC 'Secure' state, via a DNS ANY query. This results in a denial of service for installations that
  always validate (dnssec=validate) and for clients requesting validation when on-demand validation is enabled
  (dnssec=process).");

  script_tag(name:"affected", value:"PowerDNS Recursor version 4.1.17 and prior, 4.2.0 - 4.2.4 and 4.3.0 - 4.3.4.");

  script_tag(name:"solution", value:"Update to version 4.1.18, 4.2.5, 4.3.5 or later.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2020-07.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "4.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.18");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.2.0", test_version2: "4.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.5");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.5");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
