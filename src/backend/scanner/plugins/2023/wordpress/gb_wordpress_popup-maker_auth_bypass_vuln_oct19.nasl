# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:code-atlantic:popup_maker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170317");
  script_version("2023-02-24T10:08:40+0000");
  script_tag(name:"last_modification", value:"2023-02-24 10:08:40 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-23 17:28:06 +0000 (Thu, 23 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-18 14:35:00 +0000 (Fri, 18 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-17574");

  script_name("WordPress Popup Maker Plugin < 1.8.13 Authorization Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/popup-maker/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Popup Maker' is prone to an authorization
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can partially control the arguments of the do_action,
  during the initialization of the PUM_Site . Because of this, an attacker can call any method which
  contains an action starting from popmake_ or pum_ . This will lead to successful execution of
  functions which do not require arguments or require one argument as an array.");

  script_tag(name:"affected", value:"WordPress Popup Maker plugin prior to version 1.8.13.");

  script_tag(name:"solution", value:"Update to version 1.8.13 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/f9eb8bf2-85cd-413d-8234-fcd3c0456894");
  script_xref(name:"URL", value:"https://github.com/PopupMaker/Popup-Maker/blob/master/CHANGELOG.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"1.8.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.8.13", install_path:location );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
