###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_akka_http_dos_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# akka HTTP DoS Vulnerability
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

CPE = "cpe:/a:akka:http";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140486");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-03 16:48:17 +0700 (Fri, 03 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-1000118");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("akka HTTP DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_akka_http_detect.nasl");
  script_mandatory_keys("akka_http/installed");

  script_tag(name:"summary", value:"akka HTTP is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"Handling a request that carries an Accept header with an unsupported media
range starting with a wildcard but having a specific subtype (e.g. */boom) leads to a stack overflow during
negotiation of the content type. Per default, stack overflows are treated as fatal errors, so that the JVM
process will shut itself down immediately.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 10.0.6 or later.");

  script_xref(name:"URL", value:"https://doc.akka.io/docs/akka-http/10.0.6/security/2017-05-03-illegal-media-range-in-accept-header-causes-stackoverflowerror.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
