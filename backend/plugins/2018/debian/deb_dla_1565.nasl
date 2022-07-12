###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1565.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1565-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.891565");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2018-10926", "CVE-2018-10927", "CVE-2018-10928", "CVE-2018-10929", "CVE-2018-10930",
                "CVE-2018-14651", "CVE-2018-14652", "CVE-2018-14653", "CVE-2018-14659", "CVE-2018-14661");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1565-1] glusterfs security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-11-06 00:00:00 +0100 (Tue, 06 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00003.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"glusterfs on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.5.2-2+deb8u5.

We recommend that you upgrade your glusterfs packages.");
  script_tag(name:"summary", value:"Multiple security vulnerabilities were discovered in GlusterFS, a
clustered file system. Buffer overflows and path traversal issues may
lead to information disclosure, denial-of-service or the execution of
arbitrary code.

CVE-2018-14651

It was found that the fix for CVE-2018-10927, CVE-2018-10928,
CVE-2018-10929, CVE-2018-10930, and CVE-2018-10926 was incomplete.
A remote, authenticated attacker could use one of these flaws to
execute arbitrary code, create arbitrary files, or cause denial of
service on glusterfs server nodes via symlinks to relative paths.

CVE-2018-14652

The Gluster file system is vulnerable to a buffer overflow in the
'features/index' translator via the code handling the
'GF_XATTR_CLRLK_CMD' xattr in the 'pl_getxattr' function. A remote
authenticated attacker could exploit this on a mounted volume to
cause a denial of service.

CVE-2018-14653

The Gluster file system is vulnerable to a heap-based buffer
overflow in the '__server_getspec' function via the 'gf_getspec_req'
RPC message. A remote authenticated attacker could exploit this to
cause a denial of service or other potential unspecified impact.

CVE-2018-14659

The Gluster file system is vulnerable to a denial of service attack
via use of the 'GF_XATTR_IOSTATS_DUMP_KEY' xattr. A remote,
authenticated attacker could exploit this by mounting a Gluster
volume and repeatedly calling 'setxattr(2)' to trigger a state dump
and create an arbitrary number of files in the server's runtime
directory.

CVE-2018-14661

It was found that usage of snprintf function in feature/locks
translator of glusterfs server was vulnerable to a format string
attack. A remote, authenticated attacker could use this flaw to
cause remote denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"glusterfs-client", ver:"3.5.2-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"glusterfs-common", ver:"3.5.2-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"glusterfs-dbg", ver:"3.5.2-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"glusterfs-server", ver:"3.5.2-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}