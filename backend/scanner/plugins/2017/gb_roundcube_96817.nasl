###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_roundcube_96817.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# Roundcube Webmail CVE-2017-6820 Cross Site Scripting Vulnerability
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

CPE = 'cpe:/a:roundcube:webmail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108097");
  script_version("$Revision: 12083 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-13 14:00:00 +0100 (Mon, 13 Mar 2017)");
  script_bugtraq_id(96817);
  script_cve_id("CVE-2017-6820");
  script_name("Roundcube Webmail CVE-2017-6820 Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_detect.nasl");
  script_mandatory_keys("roundcube/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This host is installed with Roundcube Webmail and is prone to
  a Cross Site Scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Roundcube Webmail 1.2.x versions prior to 1.2.4 and 1.1.x
  versions prior to 1.1.8.");

  script_tag(name:"solution", value:"Upgrade Roundcube Webmail to 1.1.8 or 1.2.4.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96817");
  script_xref(name:"URL", value:"https://roundcube.net/news/2017/03/10/updates-1.2.4-and-1.1.8-released");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version: "1.1", test_version2: "1.1.7" ) ) {
  vuln = TRUE;
  fix = "1.1.8";
}

if( version_in_range( version:vers, test_version:"1.2", test_version2:"1.2.3" ) ) {
  vuln = TRUE;
  fix = "1.2.4";
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
