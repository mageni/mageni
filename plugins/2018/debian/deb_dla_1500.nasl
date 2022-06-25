###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1500.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1500-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891500");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2015-5352", "CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564", "CVE-2016-10009",
                "CVE-2016-10011", "CVE-2016-10012", "CVE-2016-10708", "CVE-2016-1908", "CVE-2016-3115",
                "CVE-2016-6515", "CVE-2017-15906");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1500-1] openssh security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-10 00:00:00 +0200 (Mon, 10 Sep 2018)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00010.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"openssh on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1:6.7p1-5+deb8u6.

We recommend that you upgrade your openssh packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been found in OpenSSH, a free implementation
of the SSH protocol suite:

CVE-2015-5352

OpenSSH incorrectly verified time window deadlines for X connections.
Remote attackers could take advantage of this flaw to bypass intended
access restrictions. Reported by Jann Horn.

CVE-2015-5600

OpenSSH improperly restricted the processing of keyboard-interactive
devices within a single connection, which could allow remote attackers
to perform brute-force attacks or cause a denial of service, in a
non-default configuration.

CVE-2015-6563

OpenSSH incorrectly handled usernames during PAM authentication. In
conjunction with an additional flaw in the OpenSSH unprivileged child
process, remote attackers could make use if this issue to perform user
impersonation. Discovered by Moritz Jodeit.

CVE-2015-6564

Moritz Jodeit discovered a use-after-free flaw in PAM support in
OpenSSH, that could be used by remote attackers to bypass
authentication or possibly execute arbitrary code.

CVE-2016-1908

OpenSSH mishandled untrusted X11 forwarding when the X server disables
the SECURITY extension. Untrusted connections could obtain trusted X11
forwarding privileges. Reported by Thomas Hoger.

CVE-2016-3115

OpenSSH improperly handled X11 forwarding data related to
authentication credentials. Remote authenticated users could make use
of this flaw to bypass intended shell-command restrictions. Identified
by github.com/tintinweb.

CVE-2016-6515

OpenSSH did not limit password lengths for password authentication.
Remote attackers could make use of this flaw to cause a denial of
service via long strings.

CVE-2016-10009

Jann Horn discovered an untrusted search path vulnerability in
ssh-agent allowing remote attackers to execute arbitrary local
PKCS#11 modules by leveraging control over a forwarded agent-socket.

CVE-2016-10011

Jann Horn discovered that OpenSSH did not properly consider the
effects of realloc on buffer contents. This may allow local users to
obtain sensitive private-key information by leveraging access to a
privilege-separated child process.

CVE-2016-10012

Guido Vranken discovered that the OpenSSH shared memory manager
did not ensure that a bounds check was enforced by all compilers,
which could allow local users to gain privileges by leveraging access
to a sandboxed privilege-separation process.

CVE-2016-10708

NULL pointer dereference and daemon crash via an out-of-sequence
NEWKEYS message.

CVE-2017-15906

Michal Zalewski reported that OpenSSH improperly prevent write
operations in readonly mode, allowing attackers to create zero-length
files.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"openssh-client", ver:"1:6.7p1-5+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-server", ver:"1:6.7p1-5+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-sftp-server", ver:"1:6.7p1-5+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh", ver:"1:6.7p1-5+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:6.7p1-5+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-krb5", ver:"1:6.7p1-5+deb8u6", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}