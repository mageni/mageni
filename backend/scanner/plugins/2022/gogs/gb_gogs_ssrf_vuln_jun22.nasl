# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:gogs:gogs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127030");
  script_version("2022-06-02T07:35:52+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:37:36 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-02 09:16:21 +0000 (Thu, 02 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-1285");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gogs < 0.12.8 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gogs_http_detect.nasl");
  script_mandatory_keys("gogs/detected");

  script_tag(name:"summary", value:"Gogs is prone to a server-side request forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The attacker is able to discover services in the internal network
  through webhook functionality. All installations accepting public traffic are affected.");

  script_tag(name:"affected", value:"Gogs prior to version 0.12.8.");

  script_tag(name:"solution", value:"Update to version 0.12.8 or later.");

  script_xref(name:"URL", value:"https://github.com/gogs/gogs/security/advisories/GHSA-w689-557m-2cvq");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/da1fbd6e-7a02-458e-9c2e-6d226c47046d/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.12.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.12.8");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
