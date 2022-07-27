# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113454");
  script_version("2019-08-08T11:22:33+0000");
  script_tag(name:"last_modification", value:"2019-08-08 11:22:33 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-08 13:03:19 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-5020");

  script_name("Yara <= 3.8.1 Denial of Service (DoS) Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_yara_ssh_detect.nasl");
  script_mandatory_keys("yara/detected");

  script_tag(name:"summary", value:"Yara is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists within the object lookup functionality.
  A specially crafted binary file can cause a negative value to be read
  to satisfy an assert, resulting in Denial of Service. An attacker can
  create a malicious binary to trigger this vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application.");
  script_tag(name:"affected", value:"Yara through version 3.8.1.");
  script_tag(name:"solution", value:"Update to version 3.9.0.");

  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2019-0781");

  exit(0);
}

CPE = "cpe:/a:virustotal:yara";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.9.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.0" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
