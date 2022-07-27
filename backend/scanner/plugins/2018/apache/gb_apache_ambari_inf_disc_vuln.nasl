###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_ambari_inf_disc_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Apache Ambari >= 2.5.0, <= 2.6.2 Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113241");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-02 11:02:53 +0200 (Thu, 02 Aug 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-8042");
  script_bugtraq_id(104869);

  script_name("Apache Ambari >= 2.5.0, <= 2.6.2 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_ambari_detect.nasl");
  script_mandatory_keys("Apache/Ambari/Installed");

  script_tag(name:"summary", value:"Apache Ambari is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Hadoop credentials are stored in the Ambari Agent informational log.");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to acquire users' Hadoop credentials.");
  script_tag(name:"affected", value:"Apache Ambari version 2.5.0 through 2.6.2.");
  script_tag(name:"solution", value:"Update to version 2.7.0.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/AMBARI/Ambari+Vulnerabilities#AmbariVulnerabilities-CVE-2018-8042");

  exit(0);
}

CPE = "cpe:/a:apache:ambari";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "2.5.0", test_version2: "2.6.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
