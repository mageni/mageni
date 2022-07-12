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
  script_oid("1.3.6.1.4.1.25623.1.0.113358");
  script_version("2019-03-25T09:51:34+0000");
  script_tag(name:"last_modification", value:"2019-03-25 09:51:34 +0000 (Mon, 25 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-20 14:31:01 +0100 (Wed, 20 Mar 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-20174", "CVE-2018-20175", "CVE-2018-20176", "CVE-2018-20177", "CVE-2018-20178",
  "CVE-2018-20179", "CVE-2018-20180", "CVE-2018-20181", "CVE-2018-20182");
  script_bugtraq_id(106938);

  script_name("rdesktop <= 1.8.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_rdesktop_detect_lin.nasl");
  script_mandatory_keys("rdesktop/detected");

  script_tag(name:"summary", value:"rdesktop is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Out-Of-Bounds Read in the function ui_clip_handle_data() that results in an information leak

  - several Integer Signedness errors that lead to Out-Of-Bounds Reads in the file mcs.c
    and result in a Denial of Service (segfault)

  - several Out-Of- Bounds Reads in the file secure.c that result in a Denial of Service (segfault)

  - Integer Overflow that leads to a Heap-Based Buffer Overflow in the function rdp_in_unistr()
    and results in memory corruption and possibly even a remote code execution

  - Out-Of-Bounds Read in the function process_demand_active() that results in a Denial of Service (segfault)

  - Integer Underflow that leads to a Heap-Based Buffer Overflow in the function lspci_process()
    and results in memory corruption and probably even a remote code execution

  - Integer Underflow that leads to a Heap-Based Buffer Overflow in the function rdpsnddbg_process()
    and results in memory corruption and probably even a remote code execution

  - Integer Underflow that leads to a Heap-Based Buffer Overflow in the function seamless_process()
    and results in memory corruption and probably even a remote code execution

  - Buffer Overflow over the global variables in the function seamless_process_line()
    that results in memory corruption and probably even a remote code execution");
  script_tag(name:"affected", value:"rdesktop through version 1.8.3.");
  script_tag(name:"solution", value:"Update to version 1.8.4.");

  script_xref(name:"URL", value:"https://research.checkpoint.com/reverse-rdp-attack-code-execution-on-rdp-clients/");

  exit(0);
}

CPE = "cpe:/a:rdesktop:rdesktop";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.8.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.4", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
