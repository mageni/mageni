# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891923");
  script_version("2019-09-17T02:00:16+0000");
  script_cve_id("CVE-2015-3908", "CVE-2015-6240", "CVE-2018-10875", "CVE-2019-10156");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-17 02:00:16 +0000 (Tue, 17 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-17 02:00:16 +0000 (Tue, 17 Sep 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1923-1] ansible security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00016.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1923-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/930065");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible'
  package(s) announced via the DSA-1923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Ansible, a configuration
management, deployment, and task execution system.

CVE-2015-3908

A potential man-in-the-middle attack associated with insusfficient
X.509 certificate verification. Ansible did not verify that the
server hostname matches a domain name in the subject's Common Name
(CN) or subjectAltName field of the X.509 certificate, which allows
man-in-the-middle attackers to spoof SSL servers via an arbitrary
valid certificate.

CVE-2015-6240

A symlink attack that allows local users to escape a restricted
environment (chroot or jail) via a symlink attack.

CVE-2018-10875

A fix potential arbitrary code execution resulting from reading
ansible.cfg from a world-writable current working directory. This
condition now causes ansible to emit a warning and ignore the
ansible.cfg in the world-writable current working directory.

CVE-2019-10156

Information disclosure through unexpected variable substitution.");

  script_tag(name:"affected", value:"'ansible' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.7.2+dfsg-2+deb8u2.

We recommend that you upgrade your ansible packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"ansible", ver:"1.7.2+dfsg-2+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ansible-doc", ver:"1.7.2+dfsg-2+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ansible-fireball", ver:"1.7.2+dfsg-2+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ansible-node-fireball", ver:"1.7.2+dfsg-2+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);