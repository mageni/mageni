# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117162");
  script_version("2021-01-18T14:42:57+0000");
  script_tag(name:"last_modification", value:"2021-01-19 11:07:43 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"creation_date", value:"2019-08-12 13:46:35 +0000 (Mon, 12 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-7614");

  script_name("Elastic Elasticsearch < 6.8.2, 7.x < 7.2.1 Information Disclosure Vulnerability (ESA-2019-07) (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Elasticsearch is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A race condition flaw was found in the response headers Elasticsearch
  returns to a request.");

  script_tag(name:"impact", value:"On a system with multiple users submitting requests, it could be possible
  for an attacker to gain access to response header containing sensitive data from another user.");

  script_tag(name:"affected", value:"Elasticsearch through version 6.8.1 and version 7.0.0 through 7.2.0.");

  script_tag(name:"solution", value:"Update to version 6.8.2 or 7.2.1 respectively.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-8-2-and-7-2-1-security-update/192963");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");

  exit(0);
}

CPE = "cpe:/a:elastic:elasticsearch";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "6.8.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.8.2", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "7.0.0", test_version2: "7.2.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "7.2.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
