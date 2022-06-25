# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108847");
  script_version("2020-08-13T11:57:16+0000");
  script_tag(name:"last_modification", value:"2020-08-14 09:58:14 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-13 11:47:22 +0000 (Thu, 13 Aug 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2020-8226");
  script_name("phpBB < 3.2.10 / 3.3.0 SSRF Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_mandatory_keys("phpBB/installed");

  script_tag(name:"summary", value:"phpBB is prone to a SSRF vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Previous versions of phpBB did allow limiting the dimensions of
  images posted. This could however also be used to e.g. check for the existence of services that
  should only be accessible from the internal network.");

  script_tag(name:"impact", value:"These flaw could be used to e.g. check for the existence of services that
  should only be accessible from the internal network.");

  script_tag(name:"affected", value:"phpBB 3.3.0 and all versions before 3.2.10.");

  script_tag(name:"solution", value:"Update to version 3.2.10, 3.3.1 or later.");

  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&t=2562631");
  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&t=2562636");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"3.2.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.10", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
} else if( version_is_equal( version:vers, test_version:"3.3.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.10", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
