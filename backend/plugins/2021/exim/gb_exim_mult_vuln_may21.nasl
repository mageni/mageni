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

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145890");
  script_version("2021-05-05T04:35:52+0000");
  script_tag(name:"last_modification", value:"2021-05-05 10:22:53 +0000 (Wed, 05 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-05 04:03:59 +0000 (Wed, 05 May 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-28007", "CVE-2020-28008", "CVE-2020-28014", "CVE-2021-27216", "CVE-2020-28011",
                "CVE-2020-28010", "CVE-2020-28013", "CVE-2020-28016", "CVE-2020-28015", "CVE-2020-28012",
                "CVE-2020-28009", "CVE-2020-28017", "CVE-2020-28020", "CVE-2020-28023", "CVE-2020-28021",
                "CVE-2020-28022", "CVE-2020-28026", "CVE-2020-28019", "CVE-2020-28024", "CVE-2020-28018",
                "CVE-2020-28025");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim < 4.94.2 Multiple Vulnerabilities (21Nails)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_exim_detect.nasl");
  script_mandatory_keys("exim/installed");

  script_tag(name:"summary", value:"Exim is prone to multiple vulnerabilities (21Nails).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-28007: Link attack in Exim's log directory

  - CVE-2020-28008: Assorted attacks in Exim's spool directory

  - CVE-2020-28014: Arbitrary file creation and clobbering

  - CVE-2021-27216: Arbitrary file deletion

  - CVE-2020-28011: Heap buffer overflow in queue_run()

  - CVE-2020-28010: Heap out-of-bounds write in main()

  - CVE-2020-28013: Heap buffer overflow in parse_fix_phrase()

  - CVE-2020-28016: Heap out-of-bounds write in parse_fix_phrase()

  - CVE-2020-28015: New-line injection into spool header file (local)

  - CVE-2020-28012: Missing close-on-exec flag for privileged pipe

  - CVE-2020-28009: Integer overflow in get_stdinput()

  - CVE-2020-28017: Integer overflow in receive_add_recipient()

  - CVE-2020-28020: Integer overflow in receive_msg()

  - CVE-2020-28023: Out-of-bounds read in smtp_setup_msg()

  - CVE-2020-28021: New-line injection into spool header file (remote)

  - CVE-2020-28022: Heap out-of-bounds read and write in extract_option()

  - CVE-2020-28026: Line truncation and injection in spool_read_header()

  - CVE-2020-28019: Failure to reset function pointer after BDAT error

  - CVE-2020-28024: Heap buffer underflow in smtp_ungetc()

  - CVE-2020-28018: Use-after-free in tls-openssl.c

  - CVE-2020-28025: Heap out-of-bounds read in pdkim_finish_bodyhash()");

  script_tag(name:"affected", value:"Exim prior to version 4.94.2.");

  script_tag(name:"solution", value:"Update to version 4.94.2 or later.");

  script_xref(name:"URL", value:"https://www.qualys.com/2021/05/04/21nails/21nails.txt");
  script_xref(name:"URL", value:"https://www.exim.org/static/doc/security/CVE-2020-qualys/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.94.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.94.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
