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
  script_oid("1.3.6.1.4.1.25623.1.0.117170");
  script_version("2021-01-19T14:54:13+0000");
  script_tag(name:"last_modification", value:"2021-01-20 11:07:43 +0000 (Wed, 20 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-19 14:15:51 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-7611");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Only Elasticsearch Security affected.

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Security < 5.6.15 / 6.x < 6.6.1 Permission Issue (ESA-2019-04)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch Security is prone to a permission issue.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A permission issue was found in Elasticsearch when Field Level Security
  and Document Level Security are disabled and the _aliases, _shrink, or _split endpoints are used . If the
  elasticsearch.yml file has xpack.security.dls_fls.enabled set to false, certain permission checks are
  skipped when users perform one of the actions mentioned above, to make existing data available under a new
  index/alias name.");

  script_tag(name:"impact", value:"This flaw could result in an attacker gaining additional permissions against
  a restricted index.");

  script_tag(name:"affected", value:"Elasticsearch Security versions before 5.6.15 and 6.6.1.");

  script_tag(name:"solution", value:"Update to version 5.6.15, 6.6.1 or later.

  Users unable to update can change the xpack.security.dls_fls.enabled setting to true in their elasticsearch.yml
  file. The default setting for this option is true.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-6-1-and-5-6-15-security-update/169077");
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

if (version_is_less(version: version, test_version: "5.6.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.6.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
