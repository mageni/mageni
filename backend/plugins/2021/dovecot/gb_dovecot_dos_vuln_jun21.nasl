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

CPE = "cpe:/a:dovecot:dovecot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117514");
  script_version("2021-06-28T11:58:37+0000");
  script_tag(name:"last_modification", value:"2021-06-29 10:13:44 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-28 11:44:06 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2020-28200");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dovecot 1.2.0 - 2.3.14 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"Sieve interpreter is not protected against abusive scripts that
  claim excessive resource usage. Especially scripts using massive amounts of regexps.");

  script_tag(name:"impact", value:"Attacker can DoS the mail delivery system by using excessive
  amount of CPU and/or reaching the lmtp/lda process limits.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dovecot version 1.2.0 through 2.3.14.");

  script_tag(name:"solution", value:"Update to version 2.3.15 or later.

  Workaround:

  Disabling the regex sieve extension avoids the worst problems. lmtp_user_concurrency_limit may
  also be helpful.");

  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-June/000460.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-June/000457.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.2.0", test_version2: "2.3.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);