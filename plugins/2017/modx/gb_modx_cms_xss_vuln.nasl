##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modx_cms_xss_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# MODX Revolution CMS XSS Vulnerability
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

CPE = 'cpe:/a:modx:revolution';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140530");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-24 09:41:29 +0700 (Fri, 24 Nov 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2017-1000223");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX Revolution CMS XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("modx_cms/installed");

  script_tag(name:"summary", value:"MODX Revolution CMS is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A stored web content injection vulnerability (WCI, a.k.a XSS) is present in
MODX Revolution CMS. An authenticated user with permissions to edit users can save malicious JavaScript as a User
Group name and potentially take control over victims' accounts. This can lead to an escalation of privileges
providing complete administrative control over the CMS.");

  script_tag(name:"affected", value:"MODX Revolution version 2.5.6 and prior.");

  script_tag(name:"solution", value:"Update to version 2.5.7 or later.");

  script_xref(name:"URL", value:"https://raw.githubusercontent.com/modxcms/revolution/v2.5.7-pl/core/docs/changelog.txt");

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
