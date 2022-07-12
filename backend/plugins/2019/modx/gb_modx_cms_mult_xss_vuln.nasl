# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112511");
  script_version("$Revision: 13601 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 13:26:11 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-07 10:42:11 +0100 (Thu, 07 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-20755", "CVE-2018-20756", "CVE-2018-20757", "CVE-2018-20758");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX Revolution CMS < 2.7.1 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("modx_cms/installed");

  script_tag(name:"summary", value:"MODX Revolution CMS is prone to multiple cross-site scripting vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"MODX Revolution versions through 2.7.0.");
  script_tag(name:"solution", value:"Upgrade to version 2.7.1 or apply the changes from the referenced github issues.");

  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/issues/14102");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/issues/14103");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/issues/14104");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/issues/14105");

  exit(0);
}

CPE = 'cpe:/a:modx:revolution';

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less(version: version, test_version: "2.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
