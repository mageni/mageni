# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893047");
  script_version("2022-06-09T14:06:34+0000");
  script_cve_id("CVE-2021-26720", "CVE-2021-3468");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-06-10 10:05:32 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 21:27:00 +0000 (Thu, 25 Feb 2021)");
  script_tag(name:"creation_date", value:"2022-06-08 01:00:10 +0000 (Wed, 08 Jun 2022)");
  script_name("Debian LTS: Security Advisory for avahi (DLA-3047-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/06/msg00009.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3047-1");
  script_xref(name:"Advisory-ID", value:"DLA-3047-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/984938");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'avahi'
  package(s) announced via the DLA-3047-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Debian package of Avahi, a framework for Multicast
DNS Service Discovery, executed the script avahi-daemon-check-dns.sh with root
privileges which would allow a local attacker to cause a denial of service or
create arbitrary empty files via a symlink attack on files under
/var/run/avahi-daemon. This script is now executed with the privileges of user
and group avahi and requires sudo in order to achieve that.

The aforementioned script has been removed from Debian 10 'Buster' onwards. The
workaround could not be implemented for Debian 9 'Stretch' because libnss-mdns
0.10 does not provide the required functionality to replace it.

Furthermore it was found (CVE-2021-3468) that the event used to signal the
termination of the client connection on the avahi Unix socket is not correctly
handled in the client_work function, allowing a local attacker to trigger an
infinite loop.");

  script_tag(name:"affected", value:"'avahi' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
0.6.32-2+deb9u1.

We recommend that you upgrade your avahi packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"avahi-autoipd", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"avahi-discover", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"avahi-dnsconfd", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"avahi-ui-utils", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"avahi-utils", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-client-dev", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-client3", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-common-data", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-common-dev", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-common3", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-compat-libdnssd-dev", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-compat-libdnssd1", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-core-dev", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-core7", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-glib-dev", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-glib1", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-gobject-dev", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-gobject0", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-qt4-1", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-qt4-dev", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-ui-dev", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-ui-gtk3-0", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-ui-gtk3-dev", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libavahi-ui0", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-avahi", ver:"0.6.32-2+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
