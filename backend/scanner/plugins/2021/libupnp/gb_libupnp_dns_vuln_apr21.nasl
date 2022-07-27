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

CPE = "cpe:/a:libupnp_project:libupnp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145814");
  script_version("2021-04-22T07:58:14+0000");
  script_tag(name:"last_modification", value:"2021-04-22 10:14:47 +0000 (Thu, 22 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-22 07:49:34 +0000 (Thu, 22 Apr 2021)");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:P");

  script_cve_id("CVE-2021-29462");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("lipupnp < 1.14.6 DNS Rebind Vulnerability (GHSA-6hqq-w3jq-9fhg)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_libupnp_consolidation.nasl");
  script_mandatory_keys("libupnp/detected");

  script_tag(name:"summary", value:"libupnp is prone to a DNS rebind vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The server part of pupnp (libupnp) is vulnerable to
  DNS-rebinding attacks because it does not check the value of the Host header.

  A remote web server can exploit this vulnerability to trick the user browser into
  triggering actions on the local UPnP services implemented using this library. Depending on the
  affected service, this could be used for data exfiltration, data tempering, etc.");

  script_tag(name:"impact", value:"This vulnerability can be used to exfiltrate the content of
  the media files exposed by a UPnP AV MediaServer server. Moreover, it could be possible to
  delete or upload files if this is enabled in the server configuration.");

  script_tag(name:"affected", value:"libupnp prior to version 1.14.6.");

  script_tag(name:"solution", value:"Update to version 1.14.6 or later.");

  script_xref(name:"URL", value:"https://github.com/pupnp/pupnp/security/advisories/GHSA-6hqq-w3jq-9fhg");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "1.14.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14.6", install_path: location);
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
