###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_jsa10779.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Junos RPD DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106948");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-13 14:46:37 +0700 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-2314");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Junos RPD DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Version");

  script_tag(name:"summary", value:"Junos OS is prone to a denial of service vulnerability in RPD due to
malformed BGP OPEN message.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"Receipt of a malformed BGP OPEN message may cause the routing protocol
daemon (rpd) process to crash and restart. By continuously sending specially crafted  BGP OPEN message packets,
an attacker can repetitively crash the rpd process causing prolonged denial of service.");

  script_tag(name:"affected", value:"This issue affects Junos OS 12.3, 13.3, 14.1, 14.2 and 15.1.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10779");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^12") {
  if ((revcomp(a: version, b: "12.3R13") < 0) &&
      (revcomp(a: version, b: "12.3R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.3R13");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "12.3X48-D50") < 0) &&
           (revcomp(a: version, b: "12.3X48") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.3X48-D50");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^13") {
  if ((revcomp(a: version, b: "13.3R10") < 0) &&
      (revcomp(a: version, b: "13.3R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.3R10");
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
  else if ((revcomp(a: version, b: "14.2R7") < 0) &&
           (revcomp(a: version, b: "14.2R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.2R7");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^15") {
  if ((revcomp(a: version, b: "15.1F6") < 0) &&
      (revcomp(a: version, b: "15.1F") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1F6");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1R4") < 0) &&
           (revcomp(a: version, b: "15.1R") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1R4");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X49-D100") < 0) &&
           (revcomp(a: version, b: "15.1X49") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D100");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X53-D50") < 0) &&
           (revcomp(a: version, b: "15.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X53-D50");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
