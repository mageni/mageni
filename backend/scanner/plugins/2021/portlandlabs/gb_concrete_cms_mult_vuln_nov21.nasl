# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:portlandlabs:concrete_cms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147191");
  script_version("2021-11-22T05:19:10+0000");
  script_tag(name:"last_modification", value:"2021-11-22 05:19:10 +0000 (Mon, 22 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-22 05:04:24 +0000 (Mon, 22 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2021-22966", "CVE-2021-40101", "CVE-2021-22968", "CVE-2021-22951",
                "CVE-2021-22967", "CVE-2021-22969", "CVE-2021-22970");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Concrete CMS < 8.5.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_concrete5_detect.nasl");
  script_mandatory_keys("concrete5/installed");

  script_tag(name:"summary", value:"Concrete CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-22966: Privilege escalation from Editor to Admin using Groups

  - CVE-2021-40101: Admin users must now provide their password when changing another user's
  password from the Dashboard

  - CVE-2021-22968: A bypass of adding remote files in Concrete CMS File manager lead to remote
  code execution

  - CVE-2021-22951: Unauthorized individuals could view password protected files using view_inline

  - CVE-2021-22967: Insecure indirect object reference (IDOR), an unauthenticated user was able to
  access restricted files by attaching them to a message in a conversation

  - CVE-2021-22969: SSRF mitigation bypass using DNS Rebind attack giving an attacker the ability
  to fetch cloud IAAS (ex AWS) IAM keys

  - CVE-2021-22970: Concrete allowed local IP importing causing the system to be vulnerable to SSRF
  attacks on the private LAN servers and SSRF mitigation bypass through DNS rebinding");

  script_tag(name:"affected", value:"Concrete CMS versions prior to 8.5.7.");

  script_tag(name:"solution", value:"Update to version 8.5.7 or later.");

  script_xref(name:"URL", value:"https://documentation.concretecms.org/developers/introduction/version-history/857-release-notes");

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

if (version_is_less(version: version, test_version: "8.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
