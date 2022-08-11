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

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117478");
  script_version("2021-06-09T11:20:15+0000");
  script_tag(name:"last_modification", value:"2021-06-10 10:19:24 +0000 (Thu, 10 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-09 10:59:29 +0000 (Wed, 09 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2021-28164");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Information Disclosure Vulnerability (GHSA-v7ff-8wcx-gmc5) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_jetty_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to an information disclosure
  vulnerability.");

  script_tag(name:"insight", value:"Release 9.4.37 introduced a more precise implementation of
  RFC3986 with regards to URI decoding, together with some new compliance modes to optionally allow
  support of some URI that may have ambiguous interpretation within the Servlet specified API
  methods behaviours. The default mode allowed % encoded . characters to be excluded for URI
  normalisation, which is correct by the RFC, but is not assumed by common Servlet
  implementations.");

  script_tag(name:"impact", value:"The default compliance mode allows requests with URIs that
  contain %2e or %2e%2e segments to access protected resources within the WEB-INF directory. For
  example a request to /context/%2e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal
  sensitive information regarding the implementation of a web application.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eclipse Jetty versions 9.4.37.v20210219 and 9.4.38.v20210224.");

  script_tag(name:"solution", value:"Update to version 9.4.39 or later. Please see the referenced
  vendor advisory for a possible workaround.");

  script_xref(name:"URL", value:"https://github.com/eclipse/jetty.project/security/advisories/GHSA-v7ff-8wcx-gmc5");

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

if (version_in_range(version: version, test_version: "9.4.37.20210219", test_version2: "9.4.38.20210224")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);