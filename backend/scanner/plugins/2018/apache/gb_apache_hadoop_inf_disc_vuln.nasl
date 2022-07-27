###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_hadoop_inf_disc_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Apache Hadoop Information Disclosure Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113089");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-23 13:34:37 +0100 (Tue, 23 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-15713");

  script_name("Apache Hadoop Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_require_ports("Services/www", 50070);
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"Apache Hadoop is prone to a Information Disclosure Vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The malicious user can construct a configuration file containing XML directives that reference sensitive files on the MapReduce job history server host.");
  script_tag(name:"impact", value:"Successful exploitation allows a cluster user to expose private files owned by the user running the MapReduce job history server process.");
  script_tag(name:"affected", value:"Apache Hadoop versions 0.23.0 through 0.23.11, 2.0.0 through 2.7.4, 2.8.0 through 2.8.2 and 3.0.0-beta1");
  script_tag(name:"solution", value:"Update to version 2.7.5, 2.8.3, 2.9.0 or 3.0.0 respectively.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/a790a251ace7213bde9f69777dedb453b1a01a6d18289c14a61d4f91@%3Cgeneral.hadoop.apache.org%3E");

  exit(0);
}

CPE = "cpe:/a:apache:hadoop";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "0.23.0", test_version2: "0.23.11" )  || version_in_range( version: version, test_version: "2.0.0", test_version2: "2.7.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.5" );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.3" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
