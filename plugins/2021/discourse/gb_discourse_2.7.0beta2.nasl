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

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117155");
  script_version("2021-01-15T09:45:20+0000");
  script_tag(name:"last_modification", value:"2021-01-15 11:06:40 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-15 09:41:33 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-3138");

  script_name("Discourse <= 2.7.0.beta1 Rate-Limit Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to a rate-limit bypass vulnerability.");

  script_tag(name:"insight", value:"A rate-limit bypass leads to a bypass of the 2FA requirement for certain forms.");

  script_tag(name:"affected", value:"Discourse up to and including version 2.7.0.beta1.");

  script_tag(name:"solution", value:"No known solution is available as of 15th January, 2021. Information regarding
  this issue will be updated once solution details are available.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://github.com/Mesh3l911/Disource");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"NoneAvailable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];

if( version_is_less( version:vers, test_version:"2.7.0" ) ||
    version_is_equal( version:vers, test_version:"2.7.0.beta1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:infos["location"] );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
