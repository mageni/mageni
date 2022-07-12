###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_cve_2004-0230.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Junos TCP Packet Processing Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105921");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-31 11:29:19 +0200 (Thu, 31 Jul 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2004-0230");
  script_bugtraq_id(10183);

  script_name("Junos TCP Packet Processing Denial of Service Vulnerability");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_ssh_junos_get_version.nasl", "gb_junos_snmp_version.nasl");
  script_mandatory_keys("Junos/Version");

  script_tag(name:"summary", value:"DoS in TCP packet processing");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable OS build is present on the target host.");

  script_tag(name:"insight", value:"For an established TCP session, TCP input validation only ensures
that sequence numbers are within the acceptable window prior to examining whether the SYN flag is set on
the segment. If the SYN flag is set, the TCP stack drops the session and sends a RST segment to the other
side. This issue only affects TCP sessions terminating on the router. Transit traffic and TCP Proxy services
are unaffected by this vulnerability.");

  script_tag(name:"impact", value:"An attacker who can guess an in-window sequence number, source and
destination address and port numbers can exploit this vulnerability to reset any established TCP session.");

  script_tag(name:"affected", value:"Junos OS 11.4, 12.1, 12.2, 12.3, 13.1, 13.2, 13.3");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As a
workaround enable TCP authentication, enable IPSec, enable the system to send ACKs for in-window RSTs and
SYN packets, enable a stateful firewall to block SYN packets on existing sessions.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10638");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (revcomp(a:version, b:"11.4R11") < 0) {
  security_message(port:0, data:version);
  exit(0);
}

if (version =~ "^12") {
  if (revcomp(a:version, b:"12.1R10") < 0) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X44-D35") < 0) &&
           (revcomp(a:version, b:"12.1X44") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X45-D25") < 0) &&
           (revcomp(a:version, b:"12.1X45") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X46-D20") < 0) &&
           (revcomp(a:version, b:"12.1X46") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.1X47-D10") < 0) &&
           (revcomp(a:version, b:"12.1X47") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.2R8") < 0) &&
           (revcomp(a:version, b:"12.2") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"12.3R6") < 0) &&
           (revcomp(a:version, b:"12.3") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
}

if (version =~ "^13") {
  if (revcomp(a:version, b:"13.1R4") < 0) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"13.2R4") < 0) &&
           (revcomp(a:version, b:"13.2") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
  else if ((revcomp(a:version, b:"13.3R2") < 0) &&
           (revcomp(a:version, b:"13.3") >= 0)) {
    security_message(port:0, data:version);
    exit(0);
  }
}
