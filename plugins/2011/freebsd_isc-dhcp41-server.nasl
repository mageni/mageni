###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_isc-dhcp41-server.nasl 14170 2019-03-14 09:24:12Z cfischer $
#
# Auto generated from VID f154a3c7-f7f4-11df-b617-00e0815b8da8
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68699");
  script_version("$Revision: 14170 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3611");
  script_name("FreeBSD Ports: isc-dhcp41-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: isc-dhcp41-server

CVE-2010-3611
ISC DHCP server 4.0 before 4.0.2, 4.1 before 4.1.2, and 4.2 before
4.2.0-P1 allows remote attackers to cause a denial of service (NULL
pointer dereference and crash) via a DHCPv6 packet containing a
Relay-Forward message without an address in the Relay-Forward
link-address field.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.isc.org/software/dhcp/advisories/cve-2010-3611");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/102047");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f154a3c7-f7f4-11df-b617-00e0815b8da8.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"isc-dhcp41-server");
if(!isnull(bver) && revcomp(a:bver, b:"4.1.0")>=0 && revcomp(a:bver, b:"4.1.2")<0) {
  txt += 'Package isc-dhcp41-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}