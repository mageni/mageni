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

CPE = "cpe:/a:tenable:nessus_network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118433");
  script_version("2022-12-22T08:37:21+0000");
  script_tag(name:"last_modification", value:"2022-12-22 08:37:21 +0000 (Thu, 22 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-20 14:06:37 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_cve_id("CVE-2015-9251", "CVE-2016-2542", "CVE-2019-11358", "CVE-2019-1547",
                "CVE-2019-1552");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Network Monitor < 5.11.0 Multiple Vulnerabilities (TNS-2019-08)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_tenable_nnm_smb_login_detect.nasl");
  script_mandatory_keys("tenable/nessus_network_monitor/detected");

  script_tag(name:"summary", value:"Tenable Nessus Network Monitor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Several third-party components (OpenSSL, jQuery and moment.js)
  were found to contain vulnerabilities, and updated versions have been made available by the
  providers.

  Nessus Network Monitor 5.11.0 updates OpenSSL to version 1.1.1d, jQuery to 3.4.1 and moment.js
  to 2.24.0 to address the identified vulnerabilities. Additionally, the InstallShield Installer
  for Windows installations has been updated to v.2016.");

  script_tag(name:"affected", value:"Tenable Nessus Network Monitor prior to version 5.11.0.");

  script_tag(name:"solution", value:"Update to version 5.11.0 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2019-08");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"5.11.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.11.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
