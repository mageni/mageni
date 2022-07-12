###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_94519_win.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# phpMyAdmin CVE-2016-4412 Open Redirection Vulnerability (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108122");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-10 12:18:02 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:N");
  script_cve_id("CVE-2016-4412");
  script_bugtraq_id(94519);
  script_name("phpMyAdmin CVE-2016-4412 Open Redirection Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a open redirection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A user can be tricked into following a link leading to phpMyAdmin, which after
  authentication redirects to another malicious site. The attacker must sniff the user's valid phpMyAdmin token.");

  script_tag(name:"affected", value:"phpMyAdmin 4.0.x prior to 4.0.10.16.");

  script_tag(name:"solution", value:"Update to version 4.0.10.16 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-57");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94519");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers =~ "^4\.0\." ) {
  if( version_is_less( version:vers, test_version:"4.0.10.16" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"4.0.10.16" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
