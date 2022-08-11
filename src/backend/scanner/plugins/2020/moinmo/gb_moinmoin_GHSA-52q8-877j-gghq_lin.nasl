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

CPE = "cpe:/a:moinmo:moinmoin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144912");
  script_version("2020-11-11T04:12:50+0000");
  script_tag(name:"last_modification", value:"2020-11-11 11:10:35 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-11 03:52:17 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2020-25074");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MoinMoin < 1.9.11 Directory Traversal Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moinmoinWiki/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MoinMoin is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The cache action in action/cache.py allows directory traversal through a
  crafted HTTP request.");

  script_tag(name:"impact", value:"An attacker who can upload attachments to the wiki can use this to achieve
  remote code execution.");

  script_tag(name:"affected", value:"MoinMoin prior to version 1.9.11.");

  script_tag(name:"solution", value:"Update to version 1.9.11 or later.");

  script_xref(name:"URL", value:"https://github.com/moinwiki/moin-1.9/security/advisories/GHSA-52q8-877j-gghq");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.9.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
