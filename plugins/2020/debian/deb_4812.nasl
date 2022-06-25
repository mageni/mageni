# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.704812");
  script_version("2020-12-16T04:00:12+0000");
  script_cve_id("CVE-2020-29479", "CVE-2020-29480", "CVE-2020-29481", "CVE-2020-29482", "CVE-2020-29483", "CVE-2020-29484", "CVE-2020-29485", "CVE-2020-29486", "CVE-2020-29566", "CVE-2020-29570", "CVE-2020-29571");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-12-16 11:44:11 +0000 (Wed, 16 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-16 04:00:12 +0000 (Wed, 16 Dec 2020)");
  script_name("Debian: Security Advisory for xen (DSA-4812-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4812.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4812-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the DSA-4812-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor:

Several security issues affecting Xenstore could result in cross
domain access (denial of service, information leaks or privilege
escalation) or denial of service against xenstored.

Additional vulnerabilities could result in guest-to-host denial of
service.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 4.11.4+57-g41a822c392-2.

We recommend that you upgrade your xen packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxencall1", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxendevicemodel1", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxenevtchn1", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxenforeignmemory1", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxengnttab1", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxenmisc4.11", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxentoolcore1", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxentoollog1", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-doc", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.11-amd64", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.11-arm64", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.11-armhf", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-common", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.11", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.11.4+57-g41a822c392-2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
