# OpenVAS Vulnerability Test
# $Id: deb_3508.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3508-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.703508");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2016-1577", "CVE-2016-2089", "CVE-2016-2116");
  script_name("Debian Security Advisory DSA 3508-1 (jasper - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-06 00:00:00 +0100 (Sun, 06 Mar 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3508.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(7|8)");
  script_tag(name:"affected", value:"jasper on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 1.900.1-13+deb7u4.

For the stable distribution (jessie), these problems have been fixed in
version 1.900.1-debian1-2.4+deb8u1.

We recommend that you upgrade your jasper packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were
discovered in JasPer, a library for manipulating JPEG-2000 files. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-1577
Jacob Baines discovered a double-free flaw in the
jas_iccattrval_destroy function. A remote attacker could exploit
this flaw to cause an application using the JasPer library to crash,
or potentially, to execute arbitrary code with the privileges of the
user running the application.

CVE-2016-2089
The Qihoo 360 Codesafe Team discovered a NULL pointer dereference
flaw within the jas_matrix_clip function. A remote attacker could
exploit this flaw to cause an application using the JasPer library
to crash, resulting in a denial-of-service.

CVE-2016-2116
Tyler Hicks discovered a memory leak flaw in the
jas_iccprof_createfrombuf function. A remote attacker could exploit
this flaw to cause the JasPer library to consume memory, resulting
in a denial-of-service.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libjasper-dev", ver:"1.900.1-13+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libjasper-runtime", ver:"1.900.1-13+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libjasper1", ver:"1.900.1-13+deb7u4", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libjasper-dev", ver:"1.900.1-debian1-2.4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libjasper-runtime", ver:"1.900.1-debian1-2.4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libjasper1:amd64", ver:"1.900.1-debian1-2.4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libjasper1:i386", ver:"1.900.1-debian1-2.4+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}