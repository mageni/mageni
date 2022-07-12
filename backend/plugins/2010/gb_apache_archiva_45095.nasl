###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_archiva_45095.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Apache Archiva Cross Site Request Forgery Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:apache:archiva";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100924");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
  script_bugtraq_id(45095);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3449", "CVE-2010-4408");

  script_name("Apache Archiva Cross Site Request Forgery Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45095");
  script_xref(name:"URL", value:"http://archiva.apache.org/download.html");
  script_xref(name:"URL", value:"http://jira.codehaus.org/browse/MRM-1438");
  script_xref(name:"URL", value:"http://archiva.apache.org/docs/1.3.2/release-notes.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_apache_archiva_detect.nasl");
  script_mandatory_keys("apache_archiva/installed");
  script_require_ports("Services/www", 8080);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the reference for more details.");
  script_tag(name:"summary", value:"Apache Archiva is prone to a cross-site request-forgery vulnerability.

Exploiting this issue may allow a remote attacker to perform certain administrative actions and gain unauthorized
access to the affected application. Other attacks are also possible.

The following versions are affected:

Archiva versions 1.0 through 1.0.3

Archiva versions 1.1 through 1.1.4

Archiva versions 1.2 through 1.2.2

Archiva versions 1.3 through 1.3.1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: vers, test_version: "1", test_version2:"1.0.3") ||
    version_in_range(version: vers, test_version: "1.1", test_version2:"1.1.4") ||
    version_in_range(version: vers, test_version: "1.2", test_version2:"1.2.2") ||
    version_in_range(version: vers, test_version: "1.3", test_version2:"1.3.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
