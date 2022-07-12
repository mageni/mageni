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
  script_oid("1.3.6.1.4.1.25623.1.0.118221");
  script_version("2021-09-14T14:59:45+0000");
  script_cve_id("CVE-2021-20117", "CVE-2021-20118");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-09-15 10:20:43 +0000 (Wed, 15 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-14 16:20:58 +0200 (Tue, 14 Sep 2021)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Tenable Nessus Agent < 8.3.1 Multiple Vulnerabilities (TNS-2021-15)");

  script_tag(name:"summary", value:"Tenable Nessus Agent is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2021-20117, CVE-2021-20118: Nessus Agent contains multiple local privilege escalation
  vulnerabilities which could allow an authenticated, local administrator to run specific
  executables on the Nessus Agent host.");

  script_tag(name:"affected", value:"Tenable Nessus Agent prior to version 8.3.1.");

  script_tag(name:"solution", value:"Update to version 8.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2021-15");

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
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

if( version_is_less( version:vers, test_version:"8.3.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.3.1", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
