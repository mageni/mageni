###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat Remote Code Execution Vulnerability - Sep14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804855");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2013-4444");
  script_bugtraq_id(69728);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2014-09-23 14:26:15 +0530 (Tue, 23 Sep 2014)");
  script_name("Apache Tomcat Remote Code Execution Vulnerability - Sep14");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128215");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2014-09/0075.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.40");

  script_tag(name:"summary", value:"This host is running Apache Tomcat and is
  prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists as the program does not
  properly verify or sanitize user-uploaded files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to upload malicious script and execute the arbitrary code.");

  script_tag(name:"affected", value:"Apache Tomcat version 7.x before 7.0.40");

  script_tag(name:"solution", value:"Upgrade to version 7.0.40 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

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

if( version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.39" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.0.40", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );