###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_AST-2017-014.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Asterisk DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.140648");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-04 12:06:46 +0700 (Thu, 04 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-17850");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A select set of SIP messages create a dialog in Asterisk. Those SIP messages
must contain a contact header. For those messages, if the header was not present and using the PJSIP channel
driver, it would cause Asterisk to crash. The severity of this vulnerability is somewhat mitigated if
authentication is enabled. If authentication is enabled a user would have to first be authorized before reaching
the crash point.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 14.x, 15.x and Certified Asterisk 13.18.");

  script_tag(name:"solution", value:"Upgrade to Version 13.18.5, 14.7.5, 15.1.5, 13.18-cert2 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-014.html");

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
    if (revcomp(a: version, b: "13.18cert2") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.18-cert2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.18.5")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.18.5");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.7.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.7.5");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.1.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1.5");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
