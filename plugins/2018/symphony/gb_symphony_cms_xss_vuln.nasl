###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symphony_cms_xss_vuln.nasl 12807 2018-12-17 08:21:35Z ckuersteiner $
#
# Symphony CMS <= 2.7.6 XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:symphony-cms:symphony_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112302");
  script_version("$Revision: 12807 $");
  script_cve_id("CVE-2017-12043");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-17 09:21:35 +0100 (Mon, 17 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-06-11 13:17:23 +0200 (Mon, 11 Jun 2018)");

  script_name("Symphony CMS <= 2.7.6 XSS Vulnerability");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_symphony_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("symphony/installed");

  script_xref(name:"URL", value:"https://github.com/symphonycms/symphony-2/commit/1ace6b31867cc83267b3550686271c9c65ac3ec0");

  script_tag(name:"summary", value:"This host is installed with Symphony CMS
  and is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"content/content.blueprintspages.php in Symphony has XSS via the pages content
page.");

  script_tag(name:"affected", value:"Symphony CMS versions through 2.7.6.");

  script_tag(name:"solution", value:"Update to version 2.7.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.7.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.7.7" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
