# OpenVAS Vulnerability Test
# $Id: deb_3446.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Auto-generated from advisory DSA 3446-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703446");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2016-0777", "CVE-2016-0778");
  script_name("Debian Security Advisory DSA 3446-1 (openssh - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-01-14 00:00:00 +0100 (Thu, 14 Jan 2016)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3446.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|7)");
  script_tag(name:"affected", value:"openssh on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy), these problems have been fixed
in version 1:6.0p1-4+deb7u3.

For the stable distribution (jessie), these problems have been fixed in
version 1:6.7p1-5+deb8u1.

For the testing distribution (stretch) and unstable distribution (sid), these
problems will be fixed in a later version.

We recommend that you upgrade your openssh packages.");
  script_tag(name:"summary", value:"The Qualys Security team discovered two vulnerabilities in the roaming
code of the OpenSSH client (an implementation of the SSH protocol
suite).

SSH roaming enables a client, in case an SSH connection breaks
unexpectedly, to resume it at a later time, provided the server also
supports it.

The OpenSSH server doesn't support roaming, but the OpenSSH client
supports it (even though it's not documented) and it's enabled by
default.

CVE-2016-0777
An information leak (memory disclosure) can be exploited by a rogue
SSH server to trick a client into leaking sensitive data from the
client memory, including for example private keys.

CVE-2016-0778
A buffer overflow (leading to file descriptor leak), can also be
exploited by a rogue SSH server, but due to another bug in the code
is possibly not exploitable, and only under certain conditions (not
the default configuration), when using ProxyCommand, ForwardAgent or
ForwardX11.

This security update completely disables the roaming code in the OpenSSH
client.

It is also possible to disable roaming by adding the (undocumented)
option UseRoaming no
to the global /etc/ssh/ssh_config file, or to the
user configuration in ~/.ssh/config, or by passing -oUseRoaming=no on
the command line.

Users with passphrase-less privates keys, especially in non interactive
setups (automated jobs using ssh, scp, rsync+ssh etc.) are advised to
update their keys if they have connected to an SSH server they don't
trust.

More details about identifying an attack and mitigations will be
available in the Qualys Security Advisory.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"openssh-client", ver:"1:6.7p1-5+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-server", ver:"1:6.7p1-5+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-sftp-server", ver:"1:6.7p1-5+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh", ver:"1:6.7p1-5+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:6.7p1-5+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-krb5", ver:"1:6.7p1-5+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-client", ver:"1:6.0p1-4+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-server", ver:"1:6.0p1-4+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh", ver:"1:6.0p1-4+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:6.0p1-4+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-krb5", ver:"1:6.0p1-4+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}