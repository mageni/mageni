# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117182");
  script_version("2021-01-25T13:39:09+0000");
  script_tag(name:"last_modification", value:"2021-01-26 11:26:04 +0000 (Tue, 26 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-25 13:07:06 +0000 (Mon, 25 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2021-22132");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Information Disclosure Vulnerability (ESA-2021-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An information disclosure flaw was found in the Elasticsearch async
  search API. Users who execute an async search will store the HTTP headers.");

  script_tag(name:"impact", value:"An Elasticsearch user with the ability to read the .tasks index could
  obtain sensitive request headers of other users in the cluster.");

  script_tag(name:"affected", value:"Elasticsearch versions starting with 7.7.0 and before 7.10.2.");

  script_tag(name:"solution", value:"Update to version 7.10.2 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elasticsearch-7-10-2-security-update/261164");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");

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

if (version_in_range(version: version, test_version: "7.7.0", test_version2: "7.10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.10.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
