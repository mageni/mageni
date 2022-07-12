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

CPE = "cpe:/a:isc:bind";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143161");
  script_version("2019-11-22T03:02:57+0000");
  script_tag(name:"last_modification", value:"2019-11-22 03:02:57 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-22 02:45:53 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2019-6477");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ISC BIND DoS Vulnerability - CVE-2019-6477 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ISC BIND is prone to a denial of service vulnerability as TCP-pipelined
  queries can bypass tcp-clients limit.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By design, BIND is intended to limit the number of TCP clients that can be
  connected at any given time. The update to this functionality introduced by CVE-2018-5743 changed how BIND
  calculates the number of concurrent TCP clients from counting the outstanding TCP queries to counting the TCP
  client connections. On a server with TCP-pipelining capability, it is possible for one TCP client to send a
  large number of DNS requests over a single connection. Each outstanding query will be handled internally as an
  independent client request, thus bypassing the new TCP clients limit.");

  script_tag(name:"impact", value:"With pipelining enabled each incoming query on a TCP connection requires a
  similar resource allocation to a query received via UDP or via TCP without pipelining enabled. A client using a
  TCP-pipelined connection to a server could consume more resources than the server has been provisioned to handle.
  When a TCP connection with a large number of pipelined queries is closed, the load on the server releasing these
  multiple resources can cause it to become unresponsive, even for queries that can be answered authoritatively
  or from cache.");

  script_tag(name:"affected", value:"BIND 9.11.6-P1 - 9.11.12, 9.12.4-P1 - 9.12.4-P2, 9.14.1 - 9.14.7 and
  9.11.5-S6 - 9.11.12-S1. Also affects all releases in the 9.15 development branch.");

  script_tag(name:"solution", value:"Update to version 9.11.13, 9.14.8, 9.15.6, 9.11.13-S1 or later.");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/cve-2019-6477");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos["version"];
proto = infos["proto"];

if (version !~ "^9\.")
  exit(99);

if (version =~ "^9\.11\.[0-9]\.S[0-9]") {
  if (version_in_range(version: version, test_version: "9.11.5.S6", test_version2: "9.11.12.S1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.13-S1");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
} else {
  if (version_in_range(version: version, test_version: "9.11.6.P1", test_version2: "9.11.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.11.13");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.12.4.P1", test_version2: "9.12.4.P2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.14.8");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.14.1", test_version2: "9.14.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.14.8");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "9.15.0", test_version2: "9.15.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.15.6");
    security_message(port: port, data: report, proto: proto);
    exit(0);
  }
}

exit(99);
