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
  script_oid("1.3.6.1.4.1.25623.1.0.117178");
  script_version("2021-01-25T13:39:09+0000");
  script_tag(name:"last_modification", value:"2021-01-26 11:26:04 +0000 (Tue, 26 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-25 13:07:06 +0000 (Mon, 25 Jan 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2019-7619");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Username Disclosure Vulnerability (ESA-2019-13)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch is prone to a username disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A username disclosure flaw was found in Elasticsearch's API Key service.");

  script_tag(name:"impact", value:"An unauthenticated attacker could send a specially crafted request and
  determine if a username exists in the Elasticsearch native realm.");

  script_tag(name:"affected", value:"The following Elasticsearch versions are affected by this flaw:

  7.0.0, 7.0.1, 7.1.0, 7.1.1, 7.2.0, 7.2.1, 7.3.0, 7.3.1, 7.3.2, 6.7.0, 6.7.1, 6.7.2, 6.8.0, 6.8.1, 6.8.2, 6.8.3");

  script_tag(name:"solution", value:"Update to version 6.8.4, 7.4.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-4-0-security-update/201831");
  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-8-4-security-update/204908");
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

affected = make_list(
  "7.0.0",
  "7.0.1",
  "7.1.0",
  "7.1.1",
  "7.2.0",
  "7.2.1",
  "7.3.0",
  "7.3.1",
  "7.3.2",
  "6.7.0",
  "6.7.1",
  "6.7.2",
  "6.8.0",
  "6.8.1",
  "6.8.2",
  "6.8.3");

foreach _affected(affected) {

  if (version == _affected) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.8.4 / 7.4.0", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
