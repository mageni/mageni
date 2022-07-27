###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_xss_vuln_PMASA-2018-7_lin.nasl 12938 2019-01-04 07:18:11Z asteins $
#
# phpMyAdmin 4.7.0 <= 4.7.6, 4.8.0 <= 4.8.3 XSRF/CSRF Vulnerability - PMASA-2018-7 (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108515");
  script_version("$Revision: 12938 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 08:18:11 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-12 07:54:53 +0100 (Wed, 12 Dec 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2018-19969");
  script_name("phpMyAdmin 4.7.0 <= 4.7.6, 4.8.0 <= 4.8.3 XSRF/CSRF Vulnerability - PMASA-2018-7 (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2018-7/");

  script_tag(name:"summary", value:"phpMyAdmin is prone to an Cross-Site Scripting (XSS) and
  Cross-Site Request Forgery (CSRF) Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"By deceiving a user to click on a crafted URL, it is possible to
  perform harmful SQL operations such as renaming databases, creating new tables/routines, deleting
  designer pages, adding/deleting users, updating user passwords, killing SQL processes, etc.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.7.0 through 4.7.6 and 4.8.0 through 4.8.3.");

  script_tag(name:"solution", value:"Update to version 4.8.4.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"4.7.0", test_version2:"4.7.6" ) ||
    version_in_range( version:vers, test_version:"4.8.0", test_version2:"4.8.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.8.4", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );