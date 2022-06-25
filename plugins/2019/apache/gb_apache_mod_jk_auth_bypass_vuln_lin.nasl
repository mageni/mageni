###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_jk_auth_bypass_vuln_lin.nasl 12929 2019-01-03 10:43:59Z asteins $
#
# Apache Tomcat JK Connector (mod_jk) < 1.2.46 Authentication Bypass Vulnerability (Linux)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:mod_jk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141819");
  script_version("$Revision: 12929 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 11:43:59 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-03 11:17:54 +0700 (Thu, 03 Jan 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-11759");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat JK Connector (mod_jk) < 1.2.46 Authentication Bypass Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_mod_jk_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache_modjk/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"The Apache Web Server (httpd) specific code that normalised the requested path
before matching it to the URI-worker map in Apache Tomcat JK (mod_jk) Connector 1.2.0 to 1.2.44 did not handle
some edge cases correctly. If only a sub-set of the URLs supported by Tomcat were exposed via httpd, then it was
possible for a specially constructed request to expose application functionality through the reverse proxy that
was not intended for clients accessing the application via the reverse proxy. It was also possible in some
configurations for a specially constructed request to bypass the access controls configured in httpd. While there
is some overlap between this issue and CVE-2018-1323, they are not identical.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Tomcat JK mod_jk Connector 1.2.0 to 1.2.44");

  script_tag(name:"solution", value:"Update to version 1.2.46 or later.");

  script_xref(name:"URL", value:"https://mail-archives.apache.org/mod_mbox/www-announce/201810.mbox/%3C16a616e5-5245-f26a-a5a4-2752b2826703%40apache.org%3E");
  script_xref(name:"URL", value:"https://www.immunit.ch/en/blog/2018/11/02/cve-2018-11759-apache-mod_jk-access-control-bypass/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: cpe, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.2.0", test_version2: "1.2.44")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.46");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
