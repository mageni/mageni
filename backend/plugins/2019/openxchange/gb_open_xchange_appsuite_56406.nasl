###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_xchange_appsuite_56406.nasl 13381 2019-01-31 10:15:33Z ckuersteiner $
#
# Open-Xchange (OX) AppSuite XSS Vulnerability (56406)
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

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141951");
  script_version("2019-03-29T08:13:51+0000");
  script_tag(name:"last_modification", value:"2019-03-29 08:13:51 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-01-31 17:11:41 +0700 (Thu, 31 Jan 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2018-13104");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Open-Xchange (OX) AppSuite XSS Vulnerability (56406)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ox_app_suite_detect.nasl");
  script_mandatory_keys("open_xchange_appsuite/installed");

  script_tag(name:"summary", value:"Content of mails added to Portal are being executed as script code. This way
malicious code within mails can get stored persistently.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"OX AppSuite version 7.8.4.");

  script_tag(name:"solution", value:"Update to version 7.8.4-rev40 or later.");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2019/Jan/46");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (!revision = get_kb_item("open_xchange_appsuite/" + port + "/revision"))
  exit(0);

version += '.' + revision;

if (version =~ "^7\.8\.4") {
  if (version_is_less(version: version, test_version: "7.8.4.40")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.8.4.40");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
