###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_AST-2018-008.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Asterisk Information Disclosure Vulnerability (AST-2018-008)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = 'cpe:/a:digium:asterisk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141178");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-13 10:18:20 +0700 (Wed, 13 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-12227");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Information Disclosure Vulnerability (AST-2018-008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When endpoint specific ACL rules block a SIP request they respond with a 403
forbidden. However, if an endpoint is not identified then a 401 unauthorized response is sent. This vulnerability
just discloses which requests hit a defined endpoint. The ACL rules cannot be bypassed to gain access to the
disclosed endpoints.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 14.x, 15.x, Certified Asterisk 13.18 and
Certified Asterisk 13.21.");

  script_tag(name:"solution", value:"Upgrade to Version 13.21.1, 14.7.7, 15.4.1, 13.18-cert4, 13.21-cert2 or
later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2018-008.html");
  script_xref(name:"URL", value:"https://issues.asterisk.org/jira/browse/ASTERISK-27818");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.") {
  if (version =~ "^13\.18cert") {
    if (revcomp(a: version, b: "13.18cert4") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.18-cert4");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else if (version =~ "13\.21cert") {
    if (revcomp(a: version, b: "13.21cert2") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.21-cert2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_in_range(version: version, test_version: "13.10.0", test_version2: "13.21.0")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.21.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.7.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.7.7");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.4.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.4.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
