# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127065");
  script_version("2022-06-30T14:04:38+0000");
  script_tag(name:"last_modification", value:"2022-06-30 14:04:38 +0000 (Thu, 30 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-29 11:38:00 +0000 (Wed, 29 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 20:29:00 +0000 (Mon, 04 Jan 2021)");

  script_cve_id("CVE-2019-12953");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Dropbear 2011.54 - 2018.76 Information Disclosure Vulnerability");

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_dropbear_consolidation.nasl");
  script_mandatory_keys("dropbear_ssh/detected");

  script_tag(name:"summary", value:"Dropbear is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An inconsistent failure delay that may lead to revealing valid usernames");

  script_tag(name:"affected", value:"Dropbear version 2011.54 through 2018.76");

  script_tag(name:"solution", value:"Update to version 2019.77 or later.");

  script_xref(name:"URL", value:"https://matt.ucc.asn.au/dropbear/CHANGES");

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

if( version_in_range( version:version, test_version:"2011.54", test_version2:"2018.76" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2019.77", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
