# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112744");
  script_version("2020-05-13T10:20:47+0000");
  script_tag(name:"last_modification", value:"2020-05-14 10:20:05 +0000 (Thu, 14 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-13 08:54:57 +0000 (Wed, 13 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-11044");

  script_name("FreeRDP > 1.2.0 & < 2.0.0 Double Free Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to a double free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A double free in update_read_cache_bitmap_v3_order crashes the client
  application if corrupted data from a manipulated server is parsed.");

  script_tag(name:"impact", value:"Successful exploitation would crash the client.");

  script_tag(name:"affected", value:"FreeRDP after 1.2.0 and before 2.0.0.");

  script_tag(name:"solution", value:"Update FreeRDP to version 2.0.0 or later.");

  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/issues/6013");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-cgqh-p732-6x2w");


  exit(0);
}

CPE = "cpe:/a:freerdp_project:freerdp";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_greater( version: version, test_version: "1.2.0" ) && version_is_less( version: version, test_version: "2.0.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
