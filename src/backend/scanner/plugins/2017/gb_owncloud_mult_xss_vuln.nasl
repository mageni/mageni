##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_xss_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# ownCloud Multiple XSS Vulnerabilities
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

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106966");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-19 13:10:50 +0700 (Wed, 19 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-8896", "CVE-2017-9338");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");

  script_tag(name:"summary", value:"ownCloud is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ownCloud is prone to multiple cross-site scripting vulnerabilities:

  - XSS on error pages by injecting code in url parameters. (CVE-2017-8896)

  - Inadequate escaping lead to XSS vulnerability in the search module. (CVE-2017-9338)");

  script_tag(name:"solution", value:"Update to ownCloud Server 8.2.12, 9.0.10, 9.1.6, 10.0.2 or later
versions.");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2017-004");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2017-007");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "8.2.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.12");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "9\.0") {
  if (version_is_less(version: version, test_version: "9.0.10")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.0.10");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "9\.1") {
  if (version_is_less(version: version, test_version: "9.1.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.1.6");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "10\.0") {
  if (version_is_less(version: version, test_version: "10.0.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "10.0.2");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
