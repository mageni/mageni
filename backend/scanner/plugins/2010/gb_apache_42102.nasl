###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_42102.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Apache 'mod_proxy_http' 2.2.9 for Unix Timeout Handling Information Disclosure Vulnerability
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100858");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-19 12:49:22 +0200 (Tue, 19 Oct 2010)");
  script_bugtraq_id(42102);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-2791");
  script_name("Apache 'mod_proxy_http' 2.2.9 for Unix Timeout Handling Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("os_detection.nasl", "secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42102");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name:"URL", value:"http://httpd.apache.org/");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/3243");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=699841");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100109771"); # nb: According to the vendor advisory: "An information disclosure flaw was found in mod_proxy_http in version 2.2.9 only,"

  script_tag(name:"affected", value:"Apache 2.2.9 on Unix is vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"Apache is prone to an information-disclosure vulnerability that
  affects the 'mod_proxy_http' module.");
  script_tag(name:"impact", value:"Attackers can leverage this issue to gain access to sensitive
  information that may aid in further attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"2.2.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.10" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );