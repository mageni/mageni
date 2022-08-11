###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_jsa10789.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Junos SRX Series: DHCP DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106945");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-13 12:42:35 +0700 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-10605");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Junos SRX Series: DHCP DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("JunOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Version", "Junos/model");

  script_tag(name:"summary", value:"Junos OS on SRX series is prone to a denial of service vulnerability in
flowd due to crafted DHCP packet.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"On all vSRX and SRX Series devices, when the DHCP or DHCP relay is
configured, specially crafted packet might cause the flowd process to crash, halting or interrupting traffic
from flowing through the device(s).

Repeated crashes of the flowd process may constitute an extended denial of service condition for the device(s).");

  script_tag(name:"impact", value:"An unauthenticated attacker may cause a denial of service condition.");

  script_tag(name:"affected", value:"Junos OS 12.1X46, 12.3X48 and 15.1X49 on SRX Series.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10789");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

model = get_kb_item("Junos/model");
if (!model || (toupper(model) !~ '^(V)?SRX'))
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if ((revcomp(a: version, b: "12.1X46-D67") < 0) &&
    (revcomp(a: version, b: "12.1X46") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.1X46-D67");
  security_message(port: 0, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "12.3X48-D55") < 0) &&
    (revcomp(a: version, b: "12.3X48") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.3X48-D55");
  security_message(port: 0, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "15.1X49-D91") < 0) &&
    (revcomp(a: version, b: "15.1X49") >= 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.1X49-D91");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
