###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_dos_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Asterisk Remote Crash Vulnerability
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

CPE = 'cpe:/a:digium:asterisk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106240");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-12 12:33:46 +0700 (Mon, 12 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Remote Crash Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Asterisk can be crashed remotely by sending an ACK to it from an endpoint
username that Asterisk does not recognize. Most SIP request types result in an 'artificial' endpoint being
looked up, but ACKs bypass this lookup. The resulting NULL pointer results in a crash when attempting to
determine if ACLs should be applied.

This issue only affects users using the PJSIP stack with Asterisk. Those users that use chan_sip are unaffected.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.10.0");

  script_tag(name:"solution", value:"Upgrade to Version 13.11.1 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2016-006.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.10") {
  if (version_is_equal(version: version, test_version: "13.10.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.11.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
