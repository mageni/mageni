###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_38494.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Apache Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer
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
  script_oid("1.3.6.1.4.1.25623.1.0.100514");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-04 12:28:05 +0100 (Thu, 04 Mar 2010)");
  script_bugtraq_id(38494, 38491);
  script_cve_id("CVE-2010-0425", "CVE-2010-0434", "CVE-2010-0408", "CVE-2007-6750");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Apache Multiple Security Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38494");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name:"URL", value:"http://httpd.apache.org/");
  script_xref(name:"URL", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=48359");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=917870");

  script_tag(name:"affected", value:"Apache versions prior to 2.2.15 are affected.");
  script_tag(name:"solution", value:"Upgrade to  Apache 2.2.15 or Later.");
  script_tag(name:"summary", value:"Apache is prone to multiple vulnerabilities.");
  script_tag(name:"impact", value:"These issues may lead to information disclosure or other attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"2.2", test_version2:"2.2.14" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.15" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );