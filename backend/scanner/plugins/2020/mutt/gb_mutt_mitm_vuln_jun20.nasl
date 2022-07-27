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

CPE = "cpe:/a:mutt:mutt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144433");
  script_version("2020-08-20T05:11:17+0000");
  script_tag(name:"last_modification", value:"2020-08-20 10:11:27 +0000 (Thu, 20 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-20 05:05:55 +0000 (Thu, 20 Aug 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-14954");

  script_name("Mutt < 1.14.4 MITM Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_mutt_detect.nasl");
  script_mandatory_keys("mutt/detected");

  script_tag(name:"summary", value:"Mutt is prone to a Man-In-The-Middle response injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Mutt has a STARTTLS buffering issue that affects IMAP, SMTP, and POP3. When a
  server sends a 'begin TLS' response, the client reads additional data (e.g., from a man-in-the-middle attacker)
  and evaluates it in a TLS context, aka 'response injection'.");

  script_tag(name:"affected", value:"Mutt version 1.14.3 and prior.");

  script_tag(name:"solution", value:"Update to version 1.14.4 or later.");

  script_xref(name:"URL", value:"http://lists.mutt.org/pipermail/mutt-announce/Week-of-Mon-20200615/000023.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.14.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
