##############################################################################
# OpenVAS Vulnerability Test
# $Id: apache_CVE_2009_1195.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Apache 'Options' and 'AllowOverride' Directives Security Bypass
# Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100211");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-28 16:49:18 +0200 (Thu, 28 May 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1195");
  script_bugtraq_id(35115);
  script_name("Apache 'Options' and 'AllowOverride' Directives Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35115");

  script_tag(name:"affected", value:"Versions prior to Apache 2.2.9 are vulnerable.");

  script_tag(name:"solution", value:"Update to version 2.2.9 or later.");

  script_tag(name:"summary", value:"Apache HTTP server is prone to a security-bypass vulnerability
  related to the handling of specific configuration directives.");

  script_tag(name:"impact", value:"A local attacker may exploit this issue to execute arbitrary code
  within the context of the webserver process. This may result in
  elevated privileges or aid in further attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2.2.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.9" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );