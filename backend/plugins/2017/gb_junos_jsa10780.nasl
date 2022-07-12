###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_jsa10780.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Junos ICMPv6 DoS Vulnerability
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

CPE = 'cpe:/o:juniper:junos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106751");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-13 08:24:49 +0200 (Thu, 13 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2016-10142");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Junos ICMPv6 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Version");

  script_tag(name:"summary", value:"Junos OS is prone to a denial of service vulnerability in ICMPv6 PTB
messages.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the IPv6 protocol specification, related to
ICMP Packet Too Big (PTB) messages.  The security implications of IP fragmentation have been discussed at length
in various RFCs. An attacker can leverage the generation of IPv6 atomic fragments to trigger the use of
fragmentation in an arbitrary IPv6 flow and can subsequently perform any type of fragmentation-based attack
against legacy IPv6 nodes that do not implement RFC 6946.  However, even nodes that already implement RFC 6946
can be subject to DoS attacks as a result of the generation of IPv6 atomic fragments.

This issue is triggered by ICMPv6 traffic destined to the device.  Transit IPv6 traffic will not cause this issue
to occur, and IPv4 is unaffected by this vulnerability.");

  script_tag(name:"impact", value:"An attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"Junos OS 12.3X48, 14.1, 14.2, 15.1, 16.1 and 16.2");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10780");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^12") {
  if ((revcomp(a: version, b: "12.3X48-D50") < 0) &&
      (revcomp(a: version, b: "12.3X48") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.3X48-D50");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^14") {
  if (revcomp(a: version, b: "14.1R8-S3") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1R8-S3");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.2R7-S6") < 0) &&
           (revcomp(a: version, b: "14.2") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.2R7-S6");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^15") {
  if ((revcomp(a: version, b: "15.1F6-S5") < 0) &&
      (revcomp(a: version, b: "15.1F") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1F6-S5");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1R4-S7") < 0) &&
           (revcomp(a: version, b: "15.1R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1R4-S7");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X49-D80") < 0) &&
           (revcomp(a: version, b: "15.1X49") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D80");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^16") {
  if (revcomp(a: version, b: "16.1R3-S3") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.1R3-S3");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "16.2R1-S3") < 0) &&
           (revcomp(a: version, b: "16.2") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.2R1-S3");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
