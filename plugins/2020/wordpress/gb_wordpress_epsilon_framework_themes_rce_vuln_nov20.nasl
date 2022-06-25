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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112841");
  script_version("2020-11-23T08:54:59+0000");
  script_tag(name:"last_modification", value:"2020-11-23 10:56:45 +0000 (Mon, 23 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-20 09:40:11 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RCE Vulnerability in WordPress Themes using the Epsilon Framework");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_theme_http_detect.nasl");
  script_mandatory_keys("wordpress/theme/detected");

  script_tag(name:"summary", value:"Multiple WordPress themes using the Epsilon Framework are prone
  to a function injection vulnerability that could lead to remote code execution (RCE).");

  script_tag(name:"insight", value:"The attacker uses POST requests to admin-ajax.php and as such
  the attack does not leave distinct log entries.");

  script_tag(name:"impact", value:"Full remote code execution (RCE) leading to site takeover is possible.");

  script_tag(name:"affected", value:"The following WordPress themes are known to be affected:

  - Shapely <=1.2.7

  - NewsMag <=2.4.1

  - Activello <=1.4.0

  - Illdy <=2.1.4

  - Allegiant <=1.2.2

  - Newspaper X <=1.3.1

  - Pixova Lite <=2.0.5

  - Brilliance <=1.2.7

  - MedZone Lite <=1.2.4

  - Regina Lite <=2.0.4

  - Transcend <=1.1.8

  - Affluent <=1.1.0

  - Bonkers <=1.0.4

  - Antreas <=1.0.2

  - NatureMag Lite <=1.0.5 (NOTE: This theme is not available anymore)");

  script_tag(name:"solution", value:"Please contact the vendor for additional information regarding
  potential updates. If none exist remove the theme.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2020/11/large-scale-attacks-target-epsilon-framework-themes/");
  script_xref(name:"URL", value:"https://blog.nintechnet.com/unauthenticated-function-injection-vulnerability-fixed-in-15-wordpress-themes/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("list_array_func.inc");

affected = make_array();

affected["cpe:/a:colorlib:activello"]         = "1.4.2";
affected["cpe:/a:colorlib:bonkers"]           = "1.0.6";
affected["cpe:/a:colorlib:illdy"]             = "2.1.7";
affected["cpe:/a:colorlib:newspaper-x"]       = "1.3.2";
affected["cpe:/a:colorlib:pixova-lite"]       = "2.0.7";
affected["cpe:/a:colorlib:shapely"]           = "1.2.9";
affected["cpe:/a:cpothemes:affluent"]         = "1.1.2";
affected["cpe:/a:cpothemes:allegiant"]        = "1.2.6";
affected["cpe:/a:cpothemes:brilliance"]       = "1.3.0";
affected["cpe:/a:cpothemes:transcend"]        = "1.2.0";
affected["cpe:/a:machothemes:antreas"]        = "1.0.7";
affected["cpe:/a:machothemes:medzone-lite"]   = "1.2.6";
affected["cpe:/a:machothemes:naturemag-lite"] = "1.0.5";
affected["cpe:/a:machothemes:newsmag"]        = "2.4.2";
affected["cpe:/a:machothemes:regina-lite"]    = "2.0.6";

cpe_list = make_list();

foreach cpe( keys( affected ) )
  cpe_list = make_list( cpe, cpe_list );

list_infos = get_app_port_from_list( cpe_list: cpe_list );

cpe  = list_infos["cpe"];
port = list_infos["port"];

infos = get_app_version_and_location( cpe: cpe, port: port, exit_no_version: TRUE );

vers = infos["version"];
path = infos["location"];

# nb: No fix available and plugin discontinued
if( cpe =~ "^cpe:/a:machothemes:naturemag-lite" ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

if( ! fix = affected[cpe] )
  exit( 0 );

if( version_is_less( version: vers, test_version: fix ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
