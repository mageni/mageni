###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_postgresql-server1.nasl 14170 2019-03-14 09:24:12Z cfischer $
#
# Auto generated from VID a8864f8f-aa9e-11e1-a284-0023ae8e59f0
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.71362");
  script_cve_id("CVE-2012-2143");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 14170 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-05-31 11:53:50 -0400 (Thu, 31 May 2012)");
  script_name("FreeBSD Ports: postgresql-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: postgresql-server");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.postgresql.org/about/news/1397/");
  script_xref(name:"URL", value:"http://git.postgresql.org/gitweb/?p=postgresql.git;a=patch;h=932ded2ed51e8333852e370c7a6dad75d9f236f9");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/a8864f8f-aa9e-11e1-a284-0023ae8e59f0.html");

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

bver = portver(pkg:"postgresql-server");
if(!isnull(bver) && revcomp(a:bver, b:"8.3")>0 && revcomp(a:bver, b:"8.3.18_1")<0) {
  txt += "Package postgresql-server version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.4")>0 && revcomp(a:bver, b:"8.4.11_1")<0) {
  txt += "Package postgresql-server version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"9.0")>0 && revcomp(a:bver, b:"9.0.7_2")<0) {
  txt += "Package postgresql-server version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"9.1")>0 && revcomp(a:bver, b:"9.1.3_1")<0) {
  txt += "Package postgresql-server version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"9.2")>0 && revcomp(a:bver, b:"9.2.b1_1")<0) {
  txt += "Package postgresql-server version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}