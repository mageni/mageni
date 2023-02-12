# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:ispyconnect:ispy";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170284");
  script_version("2023-01-19T10:10:48+0000");
  script_tag(name:"last_modification", value:"2023-01-19 10:10:48 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-17 16:03:18 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("iSpyConnect iSpy End of Life (EOL) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ispy_http_detect.nasl");
  script_mandatory_keys("ispyconnect/ispy/detected");

  script_xref(name:"URL", value:"https://www.ispyconnect.com/download.aspx");

  script_tag(name:"summary", value:"The iSpyConnect iSpy product on the remote host has reached
  the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL product is present on the target host.");

  script_tag(name:"insight", value:"The product is marked as deprecated on the download page,
  and there seems to be no new releases made in the past two years.");

  script_tag(name:"impact", value:"An EOL product is not receiving any security updates from the
  vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the
  security of this host.");

  script_tag(name:"solution", value:"Migrate to iSpyConnect Agent DVR.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("products_eol.inc");
include("list_array_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: FALSE))
  exit(0);

version = infos["version"];
if (!version)
  version = "unknown";

if (ret = product_reached_eol(cpe: CPE, version: version)) {
  report = build_eol_message(name: "iSpyConnect iSpy",
                             cpe: CPE,
                             version: version,
                             location: infos["location"],
                             eol_version: ret["eol_version"],
                             eol_date: ret["eol_date"],
                             eol_type: "prod");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
