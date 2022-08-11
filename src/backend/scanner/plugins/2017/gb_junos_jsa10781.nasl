###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_jsa10781.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Junos EX Series DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106755");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-13 08:24:49 +0200 (Thu, 13 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2017-2315");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Junos EX Series DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Version", "Junos/model");

  script_tag(name:"summary", value:"Junos OS on EX series is prone to a denial of service vulnerability in
IPv6 processing.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in IPv6 processing has been discovered that may allow a
specially crafted IPv6 Neighbor Discovery (ND) packet destined to an EX Series Ethernet Switches to cause a slow
memory leak. A malicious network-based packet flood of these crafted IPv6 NDP packets may eventually lead to
resource exhaustion and a denial of service.");

  script_tag(name:"impact", value:"An attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"Junos OS 12.3, 13.3, 14.1, 14.2, 15.1, 16.1 and 16.2");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10781");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

model =  get_kb_item("Junos/model");
if (!model || toupper(model) !~ '^EX')
  exit(99);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^12") {
  if ((revcomp(a: version, b: "12.3R12-S4") < 0) &&
      (revcomp(a: version, b: "12.3") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.3R12-S4");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^12") {
  if ((revcomp(a: version, b: "13.3R10") < 0) &&
      (revcomp(a: version, b: "12.3") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.3R10");
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
  else if ((revcomp(a: version, b: "14.1X53-D40") < 0) &&
           (revcomp(a: version, b: "14.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1X53-D40");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.1X55-D35") < 0) &&
           (revcomp(a: version, b: "14.1X55") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1X55-D35");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.2R6-S4") < 0) &&
           (revcomp(a: version, b: "14.2") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.2R6-S4");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^15") {
  if (revcomp(a: version, b: "15.1R5") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1R5");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^16") {
  if (revcomp(a: version, b: "16.1R3") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.1R3");
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
