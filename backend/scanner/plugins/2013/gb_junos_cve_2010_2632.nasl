###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2010_2632.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Junos GNU libc GLOB_LIMIT DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103950");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-14 13:05:18 +0700 (Thu, 14 Nov 2013)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2010-2632");
  script_bugtraq_id(43819);

  script_name("Junos GNU libc GLOB_LIMIT DoS Vulnerability");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Build", "Junos/Version");

  script_tag(name:"summary", value:"Remote authenticated users can cause a partial denial of
service via crafted glob expressions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"The glob implementation in libc allows authenticated remote
users to cause a denial of service via crafted glob expressions that do not match any pathnames.");

  script_tag(name:"impact", value:"Attacks against Junos OS with FTP services enabled can cause a
partial DoS.");

  script_tag(name:"affected", value:"Platforms running Junos OS 10.4, 11.4, 12.1, 12.2, 12.3,
13.1.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As
a workaround ACLs or firewall filters to limit FTP access to the router only
from trusted hosts.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43819");

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

if (revcomp(a:build2check, b:"20130912") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.4R15") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R9") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R7-S1") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.2R6") < 0) &&
             (revcomp(a:version, b:"12.2") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.3R4") < 0) &&
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
