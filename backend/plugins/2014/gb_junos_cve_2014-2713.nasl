###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2014-2713.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Junos PFE Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105904");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-29 14:26:16 +0700 (Tue, 29 Apr 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-2713");
  script_bugtraq_id(66764);

  script_name("Junos PFE Denial of Service Vulnerability");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Build", "Junos/Version", "Junos/model");

  script_tag(name:"summary", value:"Denial of Service Vulnerability through crafted IP packet.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"A crafted IP packet destined to an MX Series or T4000 router
utilizing Trio or Cassis-based PFE (Packet Forwarding Engine) modules can cause the PFE to reboot.");

  script_tag(name:"impact", value:"Remote attackers can cause the PFE to reboot resulting in a denial
of service condition.");

  script_tag(name:"affected", value:"Junos OS 11.4, 12.1, 12.2, 12.3, 13.1, 13.2, 13.3.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10621");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66764");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

model = get_kb_item("Junos/model");
if (!model || ((toupper(model) !~ '^MX') && (toupper(model) !~ '^T4000')))
  exit(99);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("Junos/Build");
if (!build)
  exit(0);

desc += "Version/Build-Date:
" + version + " / " + build;

build2check = str_replace(string:build, find:"-", replace:"");

if (revcomp(a:build2check, b:"20140320") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"11.4R11") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R9") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.2R7") < 0) &&
             (revcomp(a:version, b:"12.2") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"12.3R4-S3") < 0) &&
             (revcomp(a:version, b:"12.3") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^13") {
  if (revcomp(a:version, b:"13.1R4") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"13.2R2") < 0) &&
             (revcomp(a:version, b:"13.2") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"13.3R1") < 0) &&
             (revcomp(a:version, b:"13.3") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

exit(99);
