###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_JSA10743.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Junos Multiple cURL and libcurl Vulnerabilities
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

CPE = 'cpe:/o:juniper:junos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106069");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-07 00:05:01 +0200 (Sat, 07 May 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-3144", "CVE-2015-3145", "CVE-2014-8151", "CVE-2014-3613",
                "CVE-2014-3620", "CVE-2015-3143", "CVE-2015-3148", "CVE-2015-3153",
                "CVE-2014-3707", "CVE-2014-8150", "CVE-2014-0015");

  script_name("Junos Multiple cURL and libcurl Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Version");

  script_tag(name:"summary", value:"Junos OS is prone to multiple vulnerabilities in
cURL and libcurl.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities in Junos OS have been
resolved by updating cURL and libcurl library. These are used to support downloading
updates or importing data into a Junos device.

Libcurl and cURL were upgraded from 7.36.0 to 7.42.1");

  script_tag(name:"impact", value:"The vulnerabilities range from denial of service attacks
until information disclosure. Please check the according CVE resources for more details.");

  script_tag(name:"affected", value:"Junos OS 12.1, 12.3, 13.2, 13.3, 14.1, 14.2 and 15.1");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10743");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^12") {
  if (revcomp(a: version, b: "12.1X46-D50") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.1X46-D50");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "12.1X47-D40") < 0) &&
           (revcomp(a: version, b: "12.1X47") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.1X47-D40");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "12.3R11") < 0) &&
           (revcomp(a: version, b: "12.3") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.3R11");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "12.3X48-D30") < 0) &&
           (revcomp(a: version, b: "12.3X48") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.3X48-D30");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^13") {
  if (revcomp(a: version, b: "13.2R9") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.2R9");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "13.2X51-D39") < 0) &&
           (revcomp(a: version, b: "13.2X51") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.2X51-D39");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "13.3R8") < 0) &&
           (revcomp(a: version, b: "13.3") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.3R8");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^14") {
  if (revcomp(a: version, b: "14.1R6") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1R6");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.1X53-D30") < 0) &&
           (revcomp(a: version, b: "14.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.1X53-D30");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "14.2R5") < 0) &&
           (revcomp(a: version, b: "14.2") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.2R5");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^15") {
  if (revcomp(a: version, b: "15.1R2") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1R2");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X49-D40") < 0) &&
           (revcomp(a: version, b: "14.1X49") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D40");
    security_message(port: 0, data: report);
    exit(0);
  }
  else if ((revcomp(a: version, b: "15.1X53-D35") < 0) &&
           (revcomp(a: version, b: "15.1X53") >= 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1X53-D35");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
