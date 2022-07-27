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

CPE = "cpe:/a:dovecot:dovecot";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143931");
  script_version("2020-05-19T04:18:19+0000");
  script_tag(name:"last_modification", value:"2020-05-19 09:33:09 +0000 (Tue, 19 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-19 04:09:57 +0000 (Tue, 19 May 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2020-10957", "CVE-2020-10958", "CVE-2020-10967");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dovecot 2.3.0 < 2.3.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Dovecot is prone to multiple vulnerabilities:

  - Unauthenticated sending of malformed parameters to a NOOP command causes a NULL Pointer Dereference and crash
    in submission-login, submission, or lmtp. (CVE-2020-10957)

  - A crafted SMTP/LMTP message triggers an unauthenticated use-after-free bug in submission-login, submission, or
    lmtp, and can lead to a crash under circumstances involving many newlines after a command. (CVE-2020-10958)

  - remote unauthenticated attackers can crash the lmtp or submission process by sending mail with an empty
    localpart. (CVE-2020-10967)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dovecot versions 2.3.0 - 2.3.10.");

  script_tag(name:"solution", value:"Update to version 2.3.10.1 or later.");

  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2020-May/000438.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(port:port, cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.3.0", test_version2: "2.3.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.10.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
