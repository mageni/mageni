###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Multiple Vulnerabilities - Jan10
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100474");
  script_version("2019-05-10T11:41:35+0000");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2010-01-28 18:48:47 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_bugtraq_id(37945, 37942, 37944);
  script_cve_id("CVE-2009-2901", "CVE-2009-2902", "CVE-2009-2693");
  script_name("Apache Tomcat Multiple Vulnerabilities - Jan10");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37945");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37944");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37942");

  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=892815");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=902650");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  details.");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a directory-traversal vulnerability and to
  an authentication-bypass vulnerability.");

  script_tag(name:"impact", value:"Exploiting this issue allows attackers to delete arbitrary files
  within the context of the current working directory or gain unauthorized access to files and directories.");

  script_tag(name:"affected", value:"Tomcat 5.5.0 through 5.5.28
  Tomcat 6.0.0 through 6.0.20");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.28" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.20" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.29/6.0.21", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );