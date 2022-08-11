##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_piwigo_mult_vuln_jul17.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Piwigo Multiple Vulnerabilities
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

CPE = 'cpe:/a:piwigo:piwigo';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106921");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-05 11:11:04 +0700 (Wed, 05 Jul 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-10678", "CVE-2017-10679", "CVE-2017-10680", "CVE-2017-10681", "CVE-2017-10682");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Piwigo is prone to multiple vulnerabilities:

  - Cross-site request forgery (CSRF) vulnerability allows remote attackers to hijack the authentication of users
for requests to delete permalinks via a crafted request. (CVE-2017-10678)

  - Remote attackers may obtain sensitive information about the descriptive name of a permalink by examining the
redirect URL that is returned in a request for the permalink ID number of a private album. The permalink ID
numbers are easily guessed. (CVE-2017-10679)

  - Cross-site request forgery (CSRF) vulnerability allows remote attackers to hijack the authentication of users
for requests to change a private album to public via a crafted request. (CVE-2017-10680)

  - Cross-site request forgery (CSRF) vulnerability allows remote attackers to hijack the authentication of users
for requests to unlock albums via a crafted request. (CVE-2017-10681)

  - SQL injection vulnerability in the administrative backend allows remote users to execute arbitrary SQL commands
via the cat_false or cat_true parameter in the comments or status page to cat_options.php. (CVE-2017-10682)");

  script_tag(name:"affected", value:"Piwigo version 2.9.1 and prior.");

  script_tag(name:"solution", value:"Update to version 2.9.2 or later.");

  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/721");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
