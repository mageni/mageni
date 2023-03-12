# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/o:d-link:dir-825_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170305");
  script_version("2023-02-21T10:09:30+0000");
  script_tag(name:"last_modification", value:"2023-02-21 10:09:30 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-06 15:32:27 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-09 17:42:00 +0000 (Mon, 09 Mar 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-9122", "CVE-2020-10213", "CVE-2020-10214", "CVE-2020-10215", "CVE-2020-10216");

  script_name("D-Link DIR-825 Rev B <= 2.10 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-825 Rev. B devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-9122: D-Link DIR-825 Rev.B devices allow remote attackers to execute
  arbitrary commands via the ntp_server parameter in an ntp_sync.cgi POST request.

  - CVE-2020-10213: command injection vulnerability via POST request to set_sta_enrollee_pin.cgi

  - CVE-2020-10214: command injection vulnerability via POST request to ntp_sync.cgi

  - CVE-2020-10215: command injection vulnerability via POST request to dns_query.cgi

  - CVE-2020-10216: command injection vulnerability via POST request to system_time.cgi");

  script_tag(name:"affected", value:"D-Link DIR-825 Rev B devices through firmware version 2.10.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  The DIR-825 revision B model has entered the end-of-life process by the time these vulnerabilities
  were disclosed and therefore the vendor is unable to provide support or development to mitigate
  them.");

  script_xref(name:"URL", value:"https://github.com/kuc001/IoTFirmware/blob/master/D-Link/vulnerability1.md");
  script_xref(name:"URL", value:"https://github.com/kuc001/IoTFirmware/blob/master/D-Link/vulnerability2.md");
  script_xref(name:"URL", value:"https://github.com/kuc001/IoTFirmware/blob/master/D-Link/vulnerability3.md");
  script_xref(name:"URL", value:"https://github.com/kuc001/IoTFirmware/blob/master/D-Link/vulnerability4.md");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

hw_version = get_kb_item( "d-link/dir/hw_version" );
if ( ! hw_version )
  exit( 0 );
# nb: some of the versions might contain _Beta or other suffixes, using revcomp to be on the safe side
if ( hw_version =~ "B" ) {
  if ( revcomp( a:version, b:"2.10" ) <= 0 ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location, extra:"Hardware revision: " + hw_version );
    security_message( port:port, data:report );
  }
  exit( 0 );
} else #nb: Revisions like Gx, Rx are not affected
  exit( 99 );
