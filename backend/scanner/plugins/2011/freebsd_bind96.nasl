###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_bind96.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID fd64188d-a71d-11e0-89b4-001ec9578670
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
  script_oid("1.3.6.1.4.1.25623.1.0.69993");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
  script_cve_id("CVE-2011-2464");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: bind96");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  bind96
   bind97
   bind98

CVE-2011-2464
Unspecified vulnerability in ISC BIND 9 9.6.x before 9.6-ESV-R4-P3,
9.7.x before 9.7.3-P3, and 9.8.x before 9.8.0-P4 allows remote
attackers to cause a denial of service (named daemon crash) via a
crafted UPDATE request.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://www.isc.org/software/bind/advisories/cve-2011-2464");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/fd64188d-a71d-11e0-89b4-001ec9578670.html");

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

bver = portver(pkg:"bind96");
if(!isnull(bver) && revcomp(a:bver, b:"9.6.3.1.ESV.R4.3")<0) {
  txt += 'Package bind96 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"bind97");
if(!isnull(bver) && revcomp(a:bver, b:"9.7.3.3")<0) {
  txt += 'Package bind97 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"bind98");
if(!isnull(bver) && revcomp(a:bver, b:"9.8.0.4")<0) {
  txt += 'Package bind98 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}