###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2014-0612.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Junos Denial of Service Vulnerability for New Dynamic VPN Connections
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
  script_oid("1.3.6.1.4.1.25623.1.0.105906");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-02 11:08:01 +0700 (Fri, 02 May 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-0612");
  script_bugtraq_id(66759);

  script_name("Junos Denial of Service Vulnerability for New Dynamic VPN Connections");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Build", "Junos/Version", "Junos/model");

  script_tag(name:"summary", value:"Denial of Service Vulnerability for new dynamic VPN connections.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"On Branch SRX Series service gateways, when Dynamic IPsec VPN is
configured, a remote unauthenticated user may cause a denial of service condition where new Dynamic VPN
connections may fail for other users. This issue may also lead to high CPU consumption and disk usage which
may cause other complications.");

  script_tag(name:"impact", value:"A remote unauthenticated user may cause a denial of service
condition where new Dynamic VPN connections may fail for other users.");

  script_tag(name:"affected", value:"Junos OS 11.4 and 12.1.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As a
workaround disable dynamic IPSec VPN.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10620");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66759");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

model = get_kb_item("Junos/model");
if (!model || (toupper(model) !~ '^SRX(10|11|21|22|24|55|65)0(-[A-Z]+)?$'))
  exit(99);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("Junos/Build");
if (!build)
  exit(0);

desc += "Version/Build-Date:
" + version + " / " + build;

build2check = str_replace(string:build, find:"-", replace:"");

if (revcomp(a:build2check, b:"20140219") >= 0) {
  exit(99);
}

if (revcomp(a:version, b:"11.4R10-S1") < 0) {
  security_message(port:0, data:desc);
  exit(0);
}

if (version =~ "^12.1X") {
  if (revcomp(a:version, b:"12.1X44-D30") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X45-D20") < 0) &&
           (revcomp(a:version, b:"12.1X45") >= 0)) {
    security_message(port:0, data:desc);
  }
  else if ((revcomp(a:version, b:"12.1X45-D20") < 0) &&
           (revcomp(a:version, b:"12.1X45") >= 0)) {
    security_message(port:0, data:desc);
  }
  else if ((revcomp(a:version, b:"12.1X46-D10") < 0) &&
           (revcomp(a:version, b:"12.1X46") >= 0)) {
    security_message(port:0, data:desc);
  }
}

exit(99);
