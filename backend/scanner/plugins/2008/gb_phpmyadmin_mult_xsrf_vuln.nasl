###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_mult_xsrf_vuln.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# phpMyAdmin Multiple CSRF SQL Injection Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800210");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-23 15:23:02 +0100 (Tue, 23 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5621");
  script_bugtraq_id(32720);
  script_name("phpMyAdmin Multiple CSRF SQL Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7382");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2008-10.php");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2008-December/msg00784.html");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can compromise database, modify the data or can compromise the whole web application.");

  script_tag(name:"affected", value:"phpMyAdmin, phpMyAdmin version 2.11 to 2.11.9.3 and 3.0 to 3.1.0.9.");

  script_tag(name:"insight", value:"This flaw is due to failure in sanitizing user-supplied data before being
  used in the SQL queries via a link or IMG tag to tbl_structure.php with a modified table parameter.");

  script_tag(name:"solution", value:"Upgrade to version 2.11.9.4 or 3.1.1.0 or later.");

  script_tag(name:"summary", value:"This host is running phpMyAdmin and is prone to multiple
  CSRF Injection vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"2.11", test_version2:"2.11.9.3" ) ||
    version_in_range( version:vers, test_version:"3.0", test_version2:"3.1.0.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.11.9.4/3.1.1.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );