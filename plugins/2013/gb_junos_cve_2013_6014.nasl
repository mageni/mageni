###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2013_6014.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Junos Security issue with Proxy ARP enabled on unnumbered interface
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103952");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-18 12:34:58 +0700 (Mon, 18 Nov 2013)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:C/A:N");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2013-6014");
  script_bugtraq_id(63391);

  script_name("Junos Security Issue with Proxy ARP Enabled");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Build", "Junos/Version");

  script_tag(name:"summary", value:"New builds of Junos OS software are available from Juniper.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"When Proxy ARP is enabled on an unnumbered interface, it allows
remote attackers to perform ARP poisoning attacks and possibly obtain sensitive information via a crafted
ARP message.");

  script_tag(name:"impact", value:"An attacker can either create a denial of service attack or
might obtain some sensitive information.");

  script_tag(name:"affected", value:"Platforms running Junos OS 10.4, 11.4, 11.4X27, 12.1, 12.1X44,
12.1X45, 12.2, 12.3, or 13.1");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10595");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63391");

  exit(0);
}

include("revisions-lib.inc");

version = get_kb_item("Junos/Version");
if (!version)
  exit(0);

build = get_kb_item("Junos/Build");
if (!build)
  exit(0);

desc += "Version/Build-Date:
" + version + " / " + build;

build2check = str_replace(string:build, find:"-", replace:"");

if (revcomp(a:build2check, b:"20130918") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.4S15") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R9") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"11.4X27.44") < 0) &&
             (revcomp(a:version, b:"11.4X27") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  }
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R7") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.1X44-D20") < 0) &&
             (revcomp(a:version, b:"12.1X44") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.1X45-D15") < 0) &&
             (revcomp(a:version, b:"12.1X45") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.2R6") < 0) &&
             (revcomp(a:version, b:"12.2") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.3R3") < 0) &&
             (revcomp(a:version, b:"12.3") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  }
}

if (version =~ "^13") {
  if (revcomp(a:version, b:"13.1R3") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"13.2R1") < 0) &&
             (revcomp(a:version, b:"13.2") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

exit(99);

