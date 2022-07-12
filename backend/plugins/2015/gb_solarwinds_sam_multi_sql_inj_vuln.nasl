# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:solarwinds:server_and_application_monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105972");
  script_version("2022-01-12T11:19:42+0000");
  script_tag(name:"last_modification", value:"2022-01-13 11:12:56 +0000 (Thu, 13 Jan 2022)");
  script_tag(name:"creation_date", value:"2015-03-06 14:06:39 +0700 (Fri, 06 Mar 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-9566");

  script_name("SolarWinds Server & Application Monitor < 6.2 Multiple SQLi Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_solarwinds_sam_http_detect.nasl", "gb_solarwinds_sam_smb_login_detect.nasl");
  script_mandatory_keys("solarwinds/sam/detected");

  script_tag(name:"summary", value:"SolarWinds Server & Application Monitor (SAM) is prone to
  multiple SQL injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On both the GetAccounts and GetAccountGroups endpoints, the
  'sort' and 'dir' parameters are susceptible to boolean-/time-based, and stacked injections. The
  attacker has to be authenticated but it can be even exploited under a guest account.");

  script_tag(name:"impact", value:"An authenticated attacker might execute arbitrary SQL commands to
  compromise the application, access or modify data, or exploit latent vulnerabilities in the
  underlying database.");

  script_tag(name:"affected", value:"SolarWinds SAM version 6.1 and previous.");

  script_tag(name:"solution", value:"Update to version 6.2 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/18");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
