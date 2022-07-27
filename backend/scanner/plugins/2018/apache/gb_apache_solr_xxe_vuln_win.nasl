###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Solr XXE Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:solr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108887");
  script_version("2020-08-20T13:18:20+0000");
  script_tag(name:"last_modification", value:"2020-08-21 10:00:44 +0000 (Fri, 21 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-04-09 13:39:11 +0700 (Mon, 09 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-1308");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Solr XXE Vulnerability (SOLR-11971) (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_solr_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/solr/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Solr is prone to a XXE vulnerability.");

  script_tag(name:"insight", value:"This vulnerability relates to an XML external entity expansion (XXE) in the
  '&dataConfig=<inlinexml>' parameter of Solr's DataImportHandler. It can be used as XXE using file/ftp/http
  protocols in order to read arbitrary local files from the Solr server or the internal network.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Solr versions from 1.2.0 up to and including 6.6.2 and from 7.0.0
  up to and including 7.2.1.");

  script_tag(name:"solution", value:"Update to version 6.6.3, 7.3.0, 8.0.0 or later.");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-11971");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.2.0", test_version2: "6.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.6.3, 7.3.0, 8.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.0, 8.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
