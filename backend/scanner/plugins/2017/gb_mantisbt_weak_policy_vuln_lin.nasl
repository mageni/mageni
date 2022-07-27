###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_weak_policy_vuln_lin.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT Weak Content Security Policy Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.106612");
  script_version("$Revision: 12818 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-02-20 13:33:44 +0700 (Mon, 20 Feb 2017)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2016-7111");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MantisBT Weak Content Security Policy Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MantisBT is prone to a weak Content Security Policy vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MantisBT uses a weak Content Security Policy when using the Gravatar plugin,
which allows remote attackers to conduct cross-site scripting (XSS) attacks via unspecified vectors.");

  script_tag(name:"affected", value:"MantisBT version 2.x. and prior to version 1.3.1");

  script_tag(name:"solution", value:"Update to MantisBT 2.0.0-beta.2, 1.3.1 or later.");

  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=21263");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.1");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "2\.0\.0") {
  if (version_is_less(version: version, test_version: "2.0.0-beta2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0-beta2");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
