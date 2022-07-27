###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_portal_xss3_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# IBM WebSphere Portal Multiple XSS Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:ibm:websphere_portal';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106227");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-07 15:24:46 +0700 (Wed, 07 Sep 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-4993", "CVE-2015-4998");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Portal Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_websphere_portal_detect.nasl");
  script_mandatory_keys("ibm_websphere_portal/installed");

  script_tag(name:"summary", value:"IBM WebSphere Portal is prone to multiple cross-site scripting
vulnerabilities.");

  script_tag(name:"insight", value:"IBM WebSphere Portal is vulnerable to cross-site scripting, caused by
improper validation of user-supplied input. A remote attacker could exploit this vulnerability to execute script
in a victim's Web browser within the security context of the hosting Web site, once the URL is clicked.");

  script_tag(name:"impact", value:"An attacker could use this vulnerability to steal the victim's cookie-based
authentication credentials.");

  script_tag(name:"affected", value:"WebSphere Portal 6.1, 7, 8.0 and 8.5");

  script_tag(name:"solution", value:"Check the vendor's advisory for sulutions.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21970176");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^8\.5") {
  if (version_is_less(version: version, test_version: "8.5.0.0.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.5.0.0 CF08");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^8\.0\.0") {
  if (version_is_less(version: version, test_version: "8.0.0.1.19")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.1 CF19");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^7\.0") {
  if (version_is_less(version: version, test_version: "7.0.0.2.29")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.2 CF29");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.1\.5") {
  if (version_is_less(version: version, test_version: "6.1.5.3.27")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.1.5.3 CF27");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.1\.0") {
  if (version_is_less(version: version, test_version: "6.1.0.6.27")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.6 CF27");
    security_message(port: port, data: report);
    exit(0);
  }
}


exit(0);
