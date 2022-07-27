###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_xss_vuln_win.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT XSS Vulnerability (Windows)
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

CPE = 'cpe:/a:mantisbt:mantisbt';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106611");
  script_version("$Revision: 12818 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-02-20 13:33:44 +0700 (Mon, 20 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2016-5364");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MantisBT XSS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MantisBT is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting (XSS) vulnerability in
manage_custom_field_edit_page.php allows remote attackers to inject arbitrary web script or HTML via the return
parameter.");

  script_tag(name:"impact", value:"An authenticated attacker may conduct a cross-site scripting attack.");

  script_tag(name:"affected", value:"MantisBT version 1.2.19 and prior.");

  script_tag(name:"solution", value:"Update to MantisBT 1.2.20 or later.");

  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=20956");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.20");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
