###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_solr_rce_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Apache Solr Remote Code Execution Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113042");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-25 15:03:04 +0200 (Wed, 25 Oct 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-12629");
  script_bugtraq_id(101261);

  script_name("Apache Solr Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_solr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Apache/Solr/Installed");

  script_tag(name:"summary", value:"Apache Solr versions 5.1 until before 7.1 are vulnerable to XML Entity Expansion leading to Remote Code Execution.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the host.");
  script_tag(name:"insight", value:"Through XML Entity Expansion code from another, malicious host can be made to load and execute on the target host.");
  script_tag(name:"impact", value:"Successful exploitation would allow the attacker to execute arbitrary code on the host.");
  script_tag(name:"affected", value:"Apache Solr 5.1 through 7.0");
  script_tag(name:"solution", value:"Update to Apache Solr 7.1");

  script_xref(name:"URL", value:"http://lucene.472066.n3.nabble.com/Re-Several-critical-vulnerabilities-discovered-in-Apache-Solr-XXE-amp-RCE-td4358308.html");
  script_xref(name:"URL", value:"https://marc.info/?l=apache-announce&m=150786685013286");

  exit(0);
}

CPE = "cpe:/a:apache:solr";

include( "host_details.inc" );
include( "version_func.inc" );

if( !port = get_app_port( cpe: CPE ) ) exit( 0 );
if( !version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

# version_is_less to also allow for hotfices of version 7, which will not include a fix for the vulnerability at hand
# If there is to be a version 6.6.2 (which is not certain as of 2017-10-25) then it will contain a fix for the vulnerability. Thus it must be excluded from the vulnerable versions

if( version_is_greater_equal( version: version, test_version: "5.1" ) && version_is_less( version: version, test_version: "7.1" ) && !version_is_equal( version: version, test_version: "6.6.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.1" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 0 );
