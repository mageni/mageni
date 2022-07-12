# OpenVAS Vulnerability Test
# $Id: deb_2314_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2314-1 (puppet)
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
  script_oid("1.3.6.1.4.1.25623.1.0.70403");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_cve_id("CVE-2011-3848", "CVE-2011-3870", "CVE-2011-3869", "CVE-2011-3871");
  script_name("Debian Security Advisory DSA 2314-1 (puppet)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202314-1");
  script_tag(name:"insight", value:"Multiple security issues have been discovered in puppet, a centralized
configuration management system.  The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2011-3848

Kristian Erik Hermansen reported that an unauthenticated
directory traversal could drop any valid X.509 Certificate Signing
Request at any location on disk, with the privileges of the Puppet
Master application.

CVE-2011-3870

Ricky Zhou discovered a potential local privilege escalation in the
ssh_authorized_keys resource and theoretically in the Solaris and
AIX providers, where file ownership was given away before it was
written, leading to a possibility for a user to overwrite arbitrary
files as root, if their authorized_keys file was managed.

CVE-2011-3869

A predictable file name in the k5login type leads to the possibility
of symlink attacks which would allow the owner of the home directory
to symlink to anything on the system, and have it replaced with the
correct content of the file, which can lead to a privilege escalation
on puppet runs.

CVE-2011-3871

A potential local privilege escalation was found in the --edit mode
of 'puppet resource' due to a persistent, predictable file name,
which can result in editing an arbitrary target file, and thus be
be tricked into running that arbitrary file as the invoking
user.  This command is most commonly run as root, this leads to a
potential privilege escalation.


Additionally, this update hardens the indirector file backed terminus base
class against injection attacks based on trusted path names.


For the oldstable distribution (lenny), this problem will be fixed soon.

For the stable distribution (squeeze), this problem has been fixed in
version 2.6.2-5+squeeze1.

For the testing distribution (wheezy), this has been fixed in
version 2.7.3-3.

For the unstable distribution (sid), this problem has been fixed in
version 2.7.3-3.");

  script_tag(name:"solution", value:"We recommend that you upgrade your puppet packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to puppet
announced via advisory DSA 2314-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"puppet", ver:"2.6.2-5+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-common", ver:"2.6.2-5+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-el", ver:"2.6.2-5+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-testsuite", ver:"2.6.2-5+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster", ver:"2.6.2-5+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vim-puppet", ver:"2.6.2-5+squeeze1", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet", ver:"2.7.3-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-common", ver:"2.7.3-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-el", ver:"2.7.3-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppet-testsuite", ver:"2.7.3-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster", ver:"2.7.3-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster-common", ver:"2.7.3-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"puppetmaster-passenger", ver:"2.7.3-3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"vim-puppet", ver:"2.7.3-3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}