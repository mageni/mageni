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

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148836");
  script_version("2022-11-01T10:10:51+0000");
  script_tag(name:"last_modification", value:"2022-11-01 10:10:51 +0000 (Tue, 01 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-10-31 14:09:22 +0000 (Mon, 31 Oct 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-29 18:22:00 +0000 (Fri, 29 Oct 2021)");

  script_cve_id("CVE-2022-3498", "CVE-2022-3499", "CVE-2022-31160", "CVE-2021-41182",
                "CVE-2021-41183", "CVE-2021-41184", "CVE-2016-10744");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 10.4.0 Multiple Vulnerabilities (TNS-2022-21)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");

  script_tag(name:"summary", value:"Tenable Nessus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nessus leverages third-party software to help provide
  underlying functionality. Several of the third-party components (select2.js, jQuery UI) were
  found to contain vulnerabilities, and updated versions have been made available by the providers.
  Additionally, two separate vulnerabilities (Client Side Validation Bypass and Improper Access
  Control) were discovered, reported and fixed.

  - CVE-2022-3498: An authenticated attacker could modify the client-side behavior to bypass the
  protection mechanisms resulting in potentially unexpected interactions between the client and
  server.

  - CVE-2022-3499: An authenticated attacker could utilize the identical agent and cluster node
  linking keys to potentially allow for a scenario where unauthorized disclosure of agent logs and
  data is present.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.4.0.");

  script_tag(name:"solution", value:"Update to version 10.4.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2022-21");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
