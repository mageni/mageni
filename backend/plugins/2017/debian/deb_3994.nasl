###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 3994-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH http://greenbone.net
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.703994");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2017-14604");
  script_name("Debian Security Advisory DSA 3994-1 (nautilus - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2017-10-07 00:00:00 +0200 (Sat, 07 Oct 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3994.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");
  script_tag(name:"affected", value:"nautilus on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), this problem has not been fixed yet.

For the stable distribution (stretch), this problem has been fixed in
version 3.22.3-1+deb9u1.

For the testing distribution (buster), this problem has been fixed
in version 3.26.0-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.26.0-1.

We recommend that you upgrade your nautilus packages.");
  script_tag(name:"summary", value:"Christian Boxdorfer discovered a vulnerability in the handling of
FreeDesktop.org .desktop files in Nautilus, a file manager for the GNOME
desktop environment. An attacker can craft a .desktop file intended to run
malicious commands but displayed as an innocuous document file in Nautilus. An
user would then trust it and open the file, and Nautilus would in turn execute
the malicious content. Nautilus protection of only trusting .desktop files with
executable permission can be bypassed by shipping the .desktop file inside a
tarball.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gir1.2-nautilus-3.0", ver:"3.26.0-1", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnautilus-extension-dev", ver:"3.26.0-1", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnautilus-extension1a", ver:"3.26.0-1", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nautilus", ver:"3.26.0-1", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nautilus-data", ver:"3.26.0-1", rls:"DEB10")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gir1.2-nautilus-3.0", ver:"3.22.3-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnautilus-extension-dev", ver:"3.22.3-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnautilus-extension1a", ver:"3.22.3-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nautilus", ver:"3.22.3-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nautilus-data", ver:"3.22.3-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}