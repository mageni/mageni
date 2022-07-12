###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4112.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4112-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704112");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-17563", "CVE-2017-17564", "CVE-2017-17565", "CVE-2017-17566");
  script_name("Debian Security Advisory DSA 4112-1 (xen - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-14 00:00:00 +0100 (Wed, 14 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4112.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"xen on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1.

We recommend that you upgrade your xen packages.

For the detailed security status of xen please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/xen");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor:

CVE-2017-17563
Jan Beulich discovered that an incorrect reference count overflow
check in x86 shadow mode may result in denial of service or
privilege escalation.

CVE-2017-17564
Jan Beulich discovered that improper x86 shadow mode reference count
error handling may result in denial of service or privilege
escalation.

CVE-2017-17565
Jan Beulich discovered that an incomplete bug check in x86 log-dirty
handling may result in denial of service.

CVE-2017-17566
Jan Beulich discovered that x86 PV guests may gain access to
internally used pages which could result in denial of service or
potential privilege escalation.

In addition this update ships the Comet shim to address the Meltdown
class of vulnerabilities for guests with legacy PV kernels. In addition,
the package provides the Xen PTI stage 1
mitigation which is built-in
and enabled by default on Intel systems, but can be disabled with
`xpti=false' on the hypervisor command line (It does not make sense to
use both xpti and the Comet shim.)

Additional information can also be found in README.pti and README.comet.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libxen-4.8", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.8-amd64", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.8-arm64", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-hypervisor-4.8-armhf", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-4.8", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.8.3+comet2+shim4.10.0+comet3-1+deb9u4.1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}