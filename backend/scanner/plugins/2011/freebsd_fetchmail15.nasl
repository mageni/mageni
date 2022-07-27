###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_fetchmail15.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID f7d838f2-9039-11e0-a051-080027ef73ec
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
  script_oid("1.3.6.1.4.1.25623.1.0.69753");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-1947");
  script_name("FreeBSD Ports: fetchmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: fetchmail

CVE-2011-1947
fetchmail 5.9.9 through 6.3.19 does not properly limit the wait time
after issuing a (1) STARTTLS or (2) STLS request, which allows remote
servers to cause a denial of service (application hang) by
acknowledging the request but not sending additional packets.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.fetchmail.info/fetchmail-SA-2011-01.txt");
  script_xref(name:"URL", value:"https://gitorious.org/fetchmail/fetchmail/commit/7dc67b8cf06f74aa57525279940e180c99701314");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f7d838f2-9039-11e0-a051-080027ef73ec.html");

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

bver = portver(pkg:"fetchmail");
if(!isnull(bver) && revcomp(a:bver, b:"6.3.20")<0) {
  txt += 'Package fetchmail version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}