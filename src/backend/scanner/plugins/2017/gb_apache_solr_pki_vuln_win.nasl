###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Solr Inter-Node Communication Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108884");
  script_version("2020-08-20T13:18:20+0000");
  script_tag(name:"last_modification", value:"2020-08-21 10:00:44 +0000 (Fri, 21 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-07-10 14:38:21 +0700 (Mon, 10 Jul 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-7660");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Solr Inter-Node Communication Vulnerability (SOLR-10624) (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_solr_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/solr/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Solr uses a PKI based mechanism to secure inter-node communication when
  security is enabled. It is possible to create a specially crafted node name that does not exist as part of the
  cluster and point it to a malicious node. This can trick the nodes in cluster to believe that the malicious node
  is a member of the cluster. So, if Solr users have enabled BasicAuth authentication mechanism using the
  BasicAuthPlugin or if the user has implemented a custom Authentication plugin, which does not implement either
  'HttpClientInterceptorPlugin' or 'HttpClientBuilderPlugin', his/her servers are vulnerable to this attack. Users
  who only use SSL without basic authentication or those who use Kerberos are not affected.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Solr versions starting from 5.3.0 up to and including 5.5.4 and 6.x prior to 6.6.0.");

  script_tag(name:"solution", value:"Update to version 5.5.5, 6.6.0, 7.0.0 or later.");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-10624");

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

if (version_in_range(version: version, test_version: "5.3.0", test_version2: "5.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.5, 6.6.0, 7.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.6.0, 7.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
