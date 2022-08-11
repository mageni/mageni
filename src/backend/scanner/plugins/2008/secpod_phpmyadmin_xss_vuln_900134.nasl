##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpmyadmin_xss_vuln_900134.nasl 14010 2019-03-06 08:24:33Z cfischer $
# Description: phpMyAdmin Cross-Site Scripting Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900134");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-03 15:12:54 +0200 (Fri, 03 Oct 2008)");
  script_bugtraq_id(31327);
  script_cve_id("CVE-2008-4326");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("phpMyAdmin Cross-Site Scripting Vulnerability");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/downloads.php?relnotes=1");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31974/");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2008-8");

  script_tag(name:"summary", value:"The host is running phpMyAdmin, which is prone to Cross-Site
  Scripting Vulnerability.");

  script_tag(name:"insight", value:"Error exists in the PMA_escapeJsString() function in js_escape.lib.php
  file, which fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"affected", value:"phpMyAdmin versions prior to 2.11.9.2.");

  script_tag(name:"solution", value:"Update to version 2.11.9.2 or later.");

  script_tag(name:"impact", value:"Execution of arbitrary HTML and script code will allow attackers
  to steal cookie-based authentication credentials and to launch other attacks.");

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

if( egrep( pattern:"^2\.(([0-9]|10)(\..*)|11(\.[0-8](\..*)?|\.9(\.[01])))", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.11.9.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );