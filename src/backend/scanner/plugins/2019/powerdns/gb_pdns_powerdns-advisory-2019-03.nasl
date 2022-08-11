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

CPE = 'cpe:/a:powerdns:authoritative_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142146");
  script_version("2019-03-29T08:13:51+0000");
  script_tag(name:"last_modification", value:"2019-03-29 08:13:51 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-19 09:39:57 +0100 (Tue, 19 Mar 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-3871");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Authoritative Server RESTful Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"An issue has been found in PowerDNS Authoritative Server when the HTTP remote
backend is used in RESTful mode (without post=1 set), allowing a remote user to cause the HTTP backend to connect
to an attacker-specified host instead of the configured one, via a crafted DNS query. This can be used to cause a
denial of service by preventing the remote backend from getting a response, content spoofing if the attacker can
time its own query so that subsequent queries will use an attacker-controlled HTTP server instead of the
configured one, and possibly information disclosure if the Authoritative Server has access to internal servers.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative up to and including 4.1.6.");

  script_tag(name:"solution", value:"Upgrade to version 4.0.7, 4.1.7 or later.");

  script_xref(name:"URL", value:"https://docs.powerdns.com/authoritative/security-advisories/powerdns-advisory-2019-03.html");

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

if (version_is_less(version: version, test_version: "4.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.7");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.7");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
