# OpenVAS Vulnerability Test
# $Id: deb_2176_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2176-1 (cups)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69111");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5183", "CVE-2009-3553", "CVE-2010-0540", "CVE-2010-0542", "CVE-2010-1748", "CVE-2010-2431", "CVE-2010-2432", "CVE-2010-2941");
  script_name("Debian Security Advisory DSA 2176-1 (cups)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Common UNIX Printing
System:

CVE-2008-5183

A null pointer dereference in RSS job completion notifications
could lead to denial of service.

CVE-2009-3553

It was discovered that incorrect file descriptor handling
could lead to denial of service.

CVE-2010-0540

A cross-site request forgery vulnerability was discovered in
the web interface.

CVE-2010-0542

Incorrect memory management in the filter subsystem could lead
to denial of service.

CVE-2010-1748

Information disclosure in the web interface.

CVE-2010-2431

Emmanuel Bouillon discovered a symlink vulnerability in handling
of cache files.

CVE-2010-2432

Denial of service in the authentication code.

CVE-2010-2941

Incorrect memory management in the IPP code could lead to denial
of service or the execution of arbitrary code.");
  script_tag(name:"summary", value:"The remote host is missing an update to cups
announced via advisory DSA 2176-1.");
  script_tag(name:"solution", value:"For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.8-1+lenny9.

The stable distribution (squeeze) and the unstable distribution (sid)
had already been fixed prior to the initial Squeeze release.

We recommend that you upgrade your cups packages.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202176-1");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"cups", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-bsd", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-client", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-common", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cups-dbg", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-client", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-common", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-dbg", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcups2", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcups2-dev", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsimage2", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsys2", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsys2-dev", ver:"1.3.8-1+lenny9", rls:"DEB5")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}