##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_mult_vuln_jun16.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# NTP.org 'ntp' Multiple Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106092");
  script_version("$Revision: 12363 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-03 11:18:33 +0700 (Fri, 03 Jun 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTP.org 'ntp' Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("NTP/Installed", "NTP/Linux/Ver");
  script_require_udp_ports(123);

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd, contains
multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"ntpd contains multiple vulnerabilities:

  - CRYPTO-NAK denial of service (CVE-2016-4957).

  - Bad authentication demobilizes ephemeral associations (CVE-2016-4953).

  - Processing of spoofed server packets affects peer variables (CVE-2016-4954).

  - Autokey associations may be reset when repeatedly receiving spoofed packets (CVE-2016-4955).

  - Broadcast associations are not covered in Sec 2978 patch, which may be leveraged to flip broadcast
clients into interleave mode (CVE-2016-4956).");

  script_tag(name:"impact", value:"Unauthenticated, remote attackers may be able to spoof or send
specially crafted packets to create denial of service conditions.");

  script_tag(name:"affected", value:"Version 4.2.8p7 and prior");

  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.8p8 or later.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/321640");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");

port = 123;

if ("ntpd" >!< get_kb_item("NTP/Linux/FullVer"))
  exit(0);

if (!version = get_kb_item("NTP/Linux/Ver"))
  exit(0);

if (revcomp(a: version, b: "4.2.8p8") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8p8");
  security_message(port: port, data: report, proto:"udp");
  exit(0);
}

exit(0);

