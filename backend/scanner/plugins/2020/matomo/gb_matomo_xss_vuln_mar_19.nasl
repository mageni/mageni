# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:matomo:matomo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108705");
  script_version("2020-01-13T08:53:16+0000");
  script_tag(name:"last_modification", value:"2020-01-13 08:53:16 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-13 08:37:07 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Matomo Analytics < 3.9.0 XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_matomo_detect.nasl");
  script_mandatory_keys("matomo/installed");

  script_xref(name:"URL", value:"https://matomo.org/changelog/matomo-3-9-0/");

  script_tag(name:"summary", value:"Matomo Analytics before version 3.9.0 is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Matomo Analytics before version 3.9.0.");

  script_tag(name:"solution", value:"Update to version 3.9.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! info = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = info["version"];
path = info["location"];

if( version_is_less( version:vers, test_version:"3.9.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.9.0", install_url:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
