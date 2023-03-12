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

CPE = "cpe:/o:d-link:dir-645_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170316");
  script_version("2023-03-02T10:09:16+0000");
  script_tag(name:"last_modification", value:"2023-03-02 10:09:16 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-02-22 19:26:41 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 06:33:00 +0000 (Fri, 08 Apr 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2021-43722", "CVE-2022-32092", "CVE-2022-46475");

  script_name("D-Link DIR-645 Rev. A Devices Multiple Vulnerabilities (Mar 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-645 Rev. A devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-43722: The hnap_main function in the cgibin handler uses sprintf to format the soapaction
  header onto the stack and has no limit on the size.

  - CVE-2022-32092: Command injection vulnerability via the QUERY_STRING parameter at
  __ajax_explorer.sgi.

  - CVE-2022-46475: Stack overflow via the service= variable in the genacgi_main function.");

  script_tag(name:"affected", value:"D-Link DIR-645 Rev A devices.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note:  The vendor states that technical support for DIR-645 has ended in 31.12.2018, therefore
  most probably no effort will be made to provide a fix for these vulnerabilities.");

  script_xref(name:"URL", value:"https://github.com/Insight8991/iot/blob/main/DIR-645%20Stack%20overflow.md");
  script_xref(name:"URL", value:"https://github.com/fxc233/iot-vul/tree/main/D-Link/DIR-645");
  script_xref(name:"URL", value:"https://github.com/Insight8991/iot/blob/main/DIR-645%20genacgi%20Stack%20overflow.md");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/pages/product.aspx?id=5ec9c4690cb84e258a81704e585167bb");

  exit(0);
}

include("host_details.inc");
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

if ( hw_version =~ "A" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:location, extra:"Hardware revision: " + hw_version );
  security_message( port:port, data:report );
  exit( 0 );
} else #nb: Other revisions
  exit( 99 );
