###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_tls_cert_validation_vuln.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Asterisk TLS Certificate Common Name NULL Byte Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106173");
  script_version("$Revision: 12338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-08 16:53:09 +0700 (Mon, 08 Aug 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-3008");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk TLS Certificate Common Name NULL Byte Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a certificate bypass vulnerability.");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Asterisk does not properly handle a null byte in a domain name in the
subject's Common Name (CN) field of an X.509 certificate, when registering a SIP TLS device. This allows
man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate
Certification Authority.");

  script_tag(name:"impact", value:"A man-in-the-middle attcker may spoof arbitrary SSL servers.");

  script_tag(name:"affected", value:"Asterisk Open Source 1.8 before 1.8.32.3, 11.x before 11.17.1, 12.x
before 12.8.2, and 13.x before 13.3.2 and Certified Asterisk 1.8.28 before 1.8.28-cert5, 11.6 before
11.6-cert11, and 13.1 before 13.1-cert2.");

  script_tag(name:"solution", value:"Upgrade to Version 1.8.32.3, 11.17.1, 12.8.2, 13.3.2, 1.8.28-cert5,
11.6-cert11, 13.1-cert2 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2015-003.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^1\.8") {
  if (version =~ "^1\.8\.28cert") {
    if (revcomp(a: version, b: "1.8.28cert5") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "1.8.25-cert5");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "1.8.32.3")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "1.8.32.3");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^11\.") {
  if (version =~ "^11\.6cert") {
    if (revcomp(a: version, b: "11.6cert11") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.6-cert11");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "11.17.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.17.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^12\.") {
  if (version_is_less(version: version, test_version: "12.8.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.8.2");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^13\.") {
  if (version =~ "^13\.1cert") {
    if (revcomp(a: version, b: "13.1cert2") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.1-cert2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.3.2")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.3.2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

exit(0);
