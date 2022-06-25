###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_mult_vuln03_mar14.nasl 35578 2014-03-25 16:52:35Z Mar$pache Tomcat Multiple Vulnerabilities - 03 Mar14
#
# Apache Tomcat Multiple Vulnerabilities - 03 - Mar14
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804521");
  script_version("2019-05-10T11:41:35+0000");
  script_cve_id("CVE-2014-0033");
  script_bugtraq_id(65769);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2014-03-25 16:52:35 +0530 (Tue, 25 Mar 2014)");
  script_name("Apache Tomcat Multiple Vulnerabilities - 03 - Mar14");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Feb/131");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125392");

  script_tag(name:"summary", value:"This host is running Apache Tomcat and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to the org/apache/catalina/connector/CoyoteAdapter.java
  which does not consider the disableURLRewriting setting when handling a session ID in a URL.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct session
  fixation attacks and manipulate certain data.");

  script_tag(name:"affected", value:"Apache Tomcat version 6.0.33 through 6.0.37.");

  script_tag(name:"solution", value:"Upgrade to version 6.0.39 or later.");

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

if( version_in_range( version:vers, test_version:"6.0.33", test_version2:"6.0.37" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.0.39", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
