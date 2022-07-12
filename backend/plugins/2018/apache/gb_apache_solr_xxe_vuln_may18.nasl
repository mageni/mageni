###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_solr_xxe_vuln_may18.nasl 12068 2018-10-25 07:21:15Z mmartin $
#
# Apache Solr 6.x < 6.6.4 and 7.x < 7.3.1 XXE Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113190");
  script_version("$Revision: 12068 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 09:21:15 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-22 13:32:55 +0200 (Tue, 22 May 2018)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-8010");

  script_name("Apache Solr 6.x < 6.6.4 and 7.x < 7.3.1 XXE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_solr_detect.nasl");
  script_mandatory_keys("Apache/Solr/Installed");

  script_tag(name:"summary", value:"Apache Solr is prone to an XML external entity expansion (XXE) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists within Solr config files (solrconfig.xml, schema.xml, managed-schema).
  It can be used as XXE using file/ftp/http protocols in order to
  read arbitrary local files from the Solr server or the internal network.");
  script_tag(name:"affected", value:"Apache Solr versions 6.0.0 through 6.6.3 and 7.0.0 through 7.3.0.");
  script_tag(name:"solution", value:"Update to version 6.6.4 or 7.3.1 respectively.");

  script_xref(name:"URL", value:"https://mail-archives.apache.org/mod_mbox/www-announce/201805.mbox/%3C08a801d3f0f9%24df46d300%249dd47900%24%40apache.org%3E");

  exit(0);
}

CPE = "cpe:/a:apache:solr";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "6.0.0", test_version2: "6.6.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.6.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.0.0", test_version2: "7.3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.3.1" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
