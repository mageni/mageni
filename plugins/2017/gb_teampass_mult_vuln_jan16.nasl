###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teampass_mult_vuln_jan16.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# TeamPass Multiple Security Vulnerabilities - Jan16
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:teampass:teampass';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108141");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2015-7562", "CVE-2015-7563", "CVE-2015-7564");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-18 13:00:00 +0200 (Tue, 18 Apr 2017)");
  script_name("TeamPass Multiple Security Vulnerabilities - Jan16");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_teampass_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("teampass/installed");

  script_xref(name:"URL", value:"https://github.com/nilsteampassnet/TeamPass/pull/1140");
  script_xref(name:"URL", value:"http://teampass.net/2016-01-29-release-2.1.25");

  script_tag(name:"summary", value:"This host is installed with TeamPass and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple cross-site scripting (XSS) vulnerabilities in the (1) label value of an item or (2) name of a role.

  - Cross-site request forgery (CSRF) vulnerability.

  - Multiple SQL injection vulnerabilities in the (1) id parameter in an action_on_quick_icon action to item.query.php
  or the (2) order or (3) direction parameter in an (a) connections_logs, (b) errors_logs or (c) access_logs action to view.query.php.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and script code in a user's
  browser session in the context of an affected site and manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"TeamPass version 2.1.24 and prior.");

  script_tag(name:"solution", value:"Upgrade to TeamPass 2.1.25 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.1.25" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.1.25" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
