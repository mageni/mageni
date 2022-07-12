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

CPE = "cpe:/a:tenable:nessus_agent";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118010");
  script_version("2021-04-09T09:44:36+0000");
  script_cve_id("CVE-2019-16168");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-04-09 09:44:36 +0000 (Fri, 09 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-09 11:22:20 +0200 (Fri, 09 Apr 2021)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Tenable Nessus Agent <= 8.2.3 Third-Party Vulnerability (TNS-2021-08)");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to a vulnerability in a third-party component (sqlite).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"sqlite was found to contain a vulnerability, and an updated
  version has been made available by the provider.

  Nessus Agent 8.2.4 will update sqlite to version 3.34.1 to address the identified
  vulnerability.");

  script_tag(name:"affected", value:"Tenable Nessus Agent up to and including version 8.2.3.");

  script_tag(name:"solution", value:"Update to version 8.2.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2021-08");

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_tenable_nessus_agent_detect_smb.nasl");
  script_mandatory_keys("tenable/nessus_agent/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"8.2.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.2.4", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
