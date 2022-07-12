###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2014-0616.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Junos Oversized BGP UPDATE DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103969");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-17 11:22:01 +0700 (Fri, 17 Jan 2014)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-0616");
  script_bugtraq_id(64766);

  script_name("Junos Oversized BGP UPDATE DoS Vulnerability");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Build", "Junos/Version");

  script_tag(name:"summary", value:"Denial of Service vulnerability in routing daemon from oversized
BGP UPDATE message.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"A large BGP UPDATE message which immediately triggers a withdraw
message to be sent, as demonstrated by a long AS_PATH and a large number of BGP Communities, cause the
routing daemon to crash. This vulnerability can be triggered in both IPv4 and IPv6 environments.");

  script_tag(name:"impact", value:"Remote attackers can cause a denial of service condition on the
device.");

  script_tag(name:"affected", value:"Junos OS i10.4, 11.4, 12.1, 12.2, 12.3, 13.1, 13.2");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. For a
workaround restrict received communities and/or create an import policy to drop updates with AS_PATH longer
than a specified number. See security bulletin from Juniper for further details.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10609");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64766");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("Junos/Build");
if (!build)
  exit(0);

desc += "Version/Build-Date:
" + version + " / " + build;

build2check = str_replace(string:build, find:"-", replace:"");

if (revcomp(a:build2check, b:"20131220") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"10.4R16") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^11") {
  if (revcomp(a:version, b:"11.4R10") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

if (version =~ "^12") {
  if (version =~ "^12\.1") {
    if (revcomp(a:version, b:"12.1R8-S3") < 0) {
      security_message(port:0, data:desc);
      exit(0);
    } else if ((revcomp(a:version, b:"12.1X44-D30") < 0) &&
               (revcomp(a:version, b:"12.1X") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
    } else if ((revcomp(a:version, b:"12.1X45-D20") < 0) &&
               (revcomp(a:version, b:"12.1X45") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
    }
  } else if ((revcomp(a:version, b:"12.2R7") < 0) &&
             (revcomp(a:version, b:"12.2") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  } else if ((revcomp(a:version, b:"12.3R5") < 0) &&
             (revcomp(a:version, b:"12.3R4-S2") != 0) &&
             (revcomp(a:version, b:"12.3") >= 0)) {
      security_message(port:0, data:desc);
      exit(0);
  }
}

if (version =~ "^13") {
  if (revcomp(a:version, b:"13.1R3-S1") < 0) {
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
