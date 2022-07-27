# OpenVAS Vulnerability Test
# $Id: ubuntu_854_1.nasl 7969 2017-12-01 09:23:16Z santu $
# $Id: ubuntu_854_1.nasl 7969 2017-12-01 09:23:16Z santu $
# Description: Auto-generated from advisory USN-854-1 (libgd2)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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

include("revisions-lib.inc");
tag_solution = "The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  libgd2-noxpm                    2.0.33-2ubuntu5.4
  libgd2-xpm                      2.0.33-2ubuntu5.4

Ubuntu 8.04 LTS:
  libgd2-noxpm                    2.0.35.dfsg-3ubuntu2.1
  libgd2-xpm                      2.0.35.dfsg-3ubuntu2.1

Ubuntu 8.10:
  libgd2-noxpm                    2.0.36~rc1~dfsg-3ubuntu1.8.10.1
  libgd2-xpm                      2.0.36~rc1~dfsg-3ubuntu1.8.10.1

Ubuntu 9.04:
  libgd2-noxpm                    2.0.36~rc1~dfsg-3ubuntu1.9.04.1
  libgd2-xpm                      2.0.36~rc1~dfsg-3ubuntu1.9.04.1

Ubuntu 9.10:
  libgd2-noxpm                    2.0.36~rc1~dfsg-3ubuntu1.9.10.1
  libgd2-xpm                      2.0.36~rc1~dfsg-3ubuntu1.9.10.1

In general, a standard system upgrade is sufficient to effect the
necessary changes.

https://secure1.securityspace.com/smysecure/catid.html?in=USN-854-1";

tag_insight = "Tomas Hoger discovered that the GD library did not properly handle the
number of colors in certain malformed GD images. If a user or automated
system were tricked into processing a specially crafted GD image, an
attacker could cause a denial of service or possibly execute arbitrary
code. (CVE-2009-3546)

It was discovered that the GD library did not properly handle incorrect
color indexes. An attacker could send specially crafted input to
applications linked against libgd2 and cause a denial of service or
possibly execute arbitrary code. This issue only affected Ubuntu 6.06 LTS.
(CVE-2009-3293)

It was discovered that the GD library did not properly handle certain
malformed GIF images. If a user or automated system were tricked into
processing a specially crafted GIF image, an attacker could cause a denial
of service. This issue only affected Ubuntu 6.06 LTS. (CVE-2007-3475,
CVE-2007-3476)

It was discovered that the GD library did not properly handle large angle
degree values. An attacker could send specially crafted input to
applications linked against libgd2 and cause a denial of service. This
issue only affected Ubuntu 6.06 LTS. (CVE-2007-3477)";
tag_summary = "The remote host is missing an update to libgd2
announced via advisory USN-854-1.";

                                                                                


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307456");
 script_version("$Revision: 7969 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
 script_cve_id("CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2009-3293", "CVE-2009-3546");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Ubuntu USN-854-1 (libgd2)");



 script_category(ACT_GATHER_INFO);
 script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-854-1/");

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Ubuntu Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libgd2-dev", ver:"2.0.33-2ubuntu5.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2", ver:"2.0.33-2ubuntu5.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm-dev", ver:"2.0.33-2ubuntu5.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm", ver:"2.0.33-2ubuntu5.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm-dev", ver:"2.0.33-2ubuntu5.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm", ver:"2.0.33-2ubuntu5.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd-tools", ver:"2.0.33-2ubuntu5.4", rls:"UBUNTU6.06 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm-dev", ver:"2.0.35.dfsg-3ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm", ver:"2.0.35.dfsg-3ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm-dev", ver:"2.0.35.dfsg-3ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm", ver:"2.0.35.dfsg-3ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd-tools", ver:"2.0.35.dfsg-3ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm-dev", ver:"2.0.36~rc1~dfsg-3ubuntu1.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm", ver:"2.0.36~rc1~dfsg-3ubuntu1.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm-dev", ver:"2.0.36~rc1~dfsg-3ubuntu1.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm", ver:"2.0.36~rc1~dfsg-3ubuntu1.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd-tools", ver:"2.0.36~rc1~dfsg-3ubuntu1.8.10.1", rls:"UBUNTU8.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm-dev", ver:"2.0.36~rc1~dfsg-3ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm", ver:"2.0.36~rc1~dfsg-3ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm-dev", ver:"2.0.36~rc1~dfsg-3ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm", ver:"2.0.36~rc1~dfsg-3ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd-tools", ver:"2.0.36~rc1~dfsg-3ubuntu1.9.04.1", rls:"UBUNTU9.04")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm-dev", ver:"2.0.36~rc1~dfsg-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-noxpm", ver:"2.0.36~rc1~dfsg-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm-dev", ver:"2.0.36~rc1~dfsg-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd2-xpm", ver:"2.0.36~rc1~dfsg-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgd-tools", ver:"2.0.36~rc1~dfsg-3ubuntu1.9.10.1", rls:"UBUNTU9.10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
