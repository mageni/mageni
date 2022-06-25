##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_mod_proxy_ftp_xss_vuln_900107.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# Apache mod_proxy_ftp Wildcard Characters XSS Vulnerability
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900107");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(30560);
  script_cve_id("CVE-2008-2939");
  script_copyright("Copyright (C) 2008 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_name("Apache mod_proxy_ftp Wildcard Characters XSS Vulnerability");
  script_dependencies("secpod_apache_detect.nasl");
  script_mandatory_keys("apache/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://httpd.apache.org/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/495180");
  script_xref(name:"URL", value:"http://httpd.apache.org/docs/2.0/mod/mod_proxy_ftp.html");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=rev&revision=682871");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=rev&revision=682868");

  script_tag(name:"summary", value:"The host is running Apache, which is prone to cross-site scripting
  vulnerability.");

  script_tag(name:"insight", value:"Input passed to the module mod_proxy_ftp with wildcard character
  is not properly sanitized before returning to the user.");

  script_tag(name:"affected", value:"Apache 2.0.0 to 2.0.63 and Apache 2.2.0 to 2.2.9.");

  script_tag(name:"solution", value:"Fixed is available in the SVN repository, please see the references
  for more information.");

  script_tag(name:"impact", value:"Remote attackers can execute arbitrary script code.");

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

if( version_in_range( version:vers, test_version:"2.0.0", test_version2:"2.0.63" ) ||
    version_in_range( version:vers, test_version:"2.2.0", test_version2:"2.2.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );