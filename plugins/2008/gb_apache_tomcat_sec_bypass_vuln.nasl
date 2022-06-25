###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat RemoteFilterValve Security Bypass Vulnerability
#
# Authors: Chandan S <schandan@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800024");
  script_version("2019-05-10T11:41:35+0000");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2008-10-16 18:25:33 +0200 (Thu, 16 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-3271");
  script_bugtraq_id(31698);
  script_name("Apache Tomcat RemoteFilterValve Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-4.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=25835");

  script_tag(name:"impact", value:"Successful attempt could lead to remote code execution and attacker
  can gain access to context of the filtered value.");

  script_tag(name:"affected", value:"Apache Tomcat version 4.1.x - 4.1.31, and 5.5.0.");

  script_tag(name:"insight", value:"Flaw in the application is due to the synchronisation problem when checking
  IP addresses. This could allow user from a non permitted IP address to gain access to a context that is protected
  with a valve that extends RemoteFilterValve including the standard RemoteAddrValve and RemoteHostValve
  implementations.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 4.1.32, or 5.5.1, or later.");

  script_tag(name:"summary", value:"Apache Tomcat Server is running on this host and that is prone to
  security bypass vulnerability.");

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

if( version_in_range( version:vers, test_version:"4.1.0", test_version2:"4.1.31" ) ||
    version_is_equal( version:vers, test_version:"5.5.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.1.32/5.5.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
