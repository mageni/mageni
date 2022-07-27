##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modx_cms_mult_vuln_apr17.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# MODX Revolution CMS Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:modx:revolution';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106799");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-15 08:46:55 +0700 (Mon, 15 May 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2017-9067", "CVE-2017-9068", "CVE-2017-9069", "CVE-2017-9070", "CVE-2017-9071", "CVE-2017-1000067");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX Revolution CMS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("modx_cms/installed");

  script_tag(name:"summary", value:"MODX Revolution CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MODX Revolution CMS is prone to multiple vulnerabilities:

  - Stored XSS in UserGroup names and various other fields

  - User/email enumeration in forgot password feature

  - XSS cache poisoning via Host header

  - Reflected XSS in setup

  - Local file inclusion vulnerability in setup action parameter

  - Various local file inclusion preventions to also protect on windows

  - Stored XSS in resource pagetitle

  - Blind SQL injection

  - PHP code execution");

  script_tag(name:"affected", value:"Version 2.5.6 and prior.");

  script_tag(name:"solution", value:"Update to version 2.5.7");

  script_xref(name:"URL", value:"https://raw.githubusercontent.com/modxcms/revolution/v2.5.7-pl/core/docs/changelog.txt");
  script_xref(name:"URL", value:"https://bitflipper.eu/finding/2017/05/modx-revolution-256-blind-sql-injection.html");
  script_xref(name:"URL", value:"https://bitflipper.eu/finding/2017/05/modx-revolution-256-php-code-execution.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
