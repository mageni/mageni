###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaltura_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Kaltura Server Multiple Vulnerabilities
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

CPE = "cpe:/a:kaltura:kaltura";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140397");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-26 10:46:06 +0700 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-14141", "CVE-2017-14142", "CVE-2017-14143");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kaltura Server Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kaltura_community_edition_detect.nasl");
  script_mandatory_keys("kaltura/installed");

  script_tag(name:"summary", value:"Kaltura Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Kaltura Server is prone to multiple vulnerabilities:

  - Authenticated Remote Code Execution through unserialize() in the admin panel (CVE-2017-14141)

  - Multiple Cross-Site Scripting vulnerabilities under the API path (CVE-2017-14142)

  - Unauthenticated Remote Code Execution through unserialize() from cookie data (CVE-2017-14143)");

  script_tag(name:"affected", value:"Kaltura Server 13.1.0 and prior.");

  script_tag(name:"solution", value:"Update to version 13.2.0 or later.");

  script_xref(name:"URL", value:"https://telekomsecurity.github.io/assets/advisories/20170912_kaltura-advisory.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "13.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.2.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
