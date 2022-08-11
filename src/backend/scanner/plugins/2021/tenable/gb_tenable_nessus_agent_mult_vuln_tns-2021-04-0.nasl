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
  script_oid("1.3.6.1.4.1.25623.1.0.118009");
  script_version("2021-04-08T12:12:30+0000");
  script_cve_id("CVE-2021-23840", "CVE-2021-23841", "CVE-2021-20077");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-04-08 12:12:30 +0000 (Thu, 08 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-08 12:07:17 +0200 (Thu, 08 Apr 2021)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Tenable Nessus Agent 7.2.0 - 8.2.2 Multiple Vulnerabilities (TNS-2021-04)");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The application was found to inadvertently capture the IAM role
  security token on the local host during initial linking of the Nessus Agent when installed on
  an Amazon EC2 instance. This could allow a privileged attacker to obtain the token.

  Additionally, one third-party component (OpenSSL) was found to contain vulnerabilities, and
  updated versions have been made available by the provider. Nessus Agent version 8.2.3 will
  update OpenSSL to 1.1.1j.");

  script_tag(name:"affected", value:"Tenable Nessus Agent version 7.2.0 through 8.2.2.");

  script_tag(name:"solution", value:"Update to version 8.2.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2021-04-0");

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

if( version_in_range( version:vers, test_version:"7.2.0", test_version2:"8.2.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.2.3", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
