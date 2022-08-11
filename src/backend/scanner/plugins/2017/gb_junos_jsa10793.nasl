###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_jsa10793.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Junos SNMPD RCE Vulnerability
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

CPE = 'cpe:/o:juniper:junos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106941");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-13 09:23:17 +0700 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-2345");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Junos SNMPD RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Version");

  script_tag(name:"summary", value:"Junos OS is prone to a remote code execution vulnerability when receiving
a crafted SNMP packet.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"On Junos OS devices with SNMP enabled, a network based attacker with
unfiltered access to the RE can cause the Junos OS snmpd daemon to crash and restart by sending a crafted SNMP
packet. Repeated crashes of the snmpd daemon can result in a partial denial of service condition. Additionally,
it may be possible to craft a malicious SNMP packet in a way that can result in remote code execution.");

  script_tag(name:"impact", value:"An unauthenticated attacker may cause a denial of service condition or
execute arbitrary code.");

  script_tag(name:"affected", value:"Junos OS 10.2 and above.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10793");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (revcomp(a: version, b: "10.2") < 0)
  exit(99);

if (version =~ "^12") {
  if ((revcomp(a: version, b: "12.1X46-D67") < 0) &&
      (revcomp(a: version, b: "12.1X46") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.1X46-D67");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "12.3X48-D51") < 0) &&
           (revcomp(a: version, b: "12.3X48") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.3X48-D51");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^13") {
  if (revcomp(a: version, b: "13.3R10-S2") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.3R10-S2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^14") {
  if ((revcomp(a: version, b: "14.1R9") < 0) &&
      (revcomp(a: version, b: "14.1R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1R9");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.1X53-D44") < 0) &&
           (revcomp(a: version, b: "14.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1X53-D44");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.2R7-S7") < 0) &&
           (revcomp(a: version, b: "14.2R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.2R7-S7");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^15") {
  if ((revcomp(a: version, b: "15.1F2-S18") < 0) &&
      (revcomp(a: version, b: "15.1F2") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1F2-S18");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1F6-S7") < 0) &&
           (revcomp(a: version, b: "15.1F6") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1F6-S7");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1R7") < 0) &&
           (revcomp(a: version, b: "15.1R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1R7");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X49-D100") < 0) &&
           (revcomp(a: version, b: "15.1X49") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D100");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X53-D47") < 0) &&
           (revcomp(a: version, b: "15.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X53-D47");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^16") {
  if (revcomp(a: version, b: "16.1R5") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.1R5");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "16.2R2") < 0) &&
           (revcomp(a: version, b: "16.2R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.2R2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^17") {
  if (revcomp(a: version, b: "17.1R2") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "17.1R2");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "17.2R2") < 0) &&
           (revcomp(a: version, b: "17.2R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "17.2R2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
