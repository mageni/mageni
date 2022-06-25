# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704830");
  script_version("2021-01-16T04:00:07+0000");
  script_cve_id("CVE-2021-21261");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-01-18 11:03:31 +0000 (Mon, 18 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-16 04:00:07 +0000 (Sat, 16 Jan 2021)");
  script_name("Debian: Security Advisory for flatpak (DSA-4830-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4830.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4830-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flatpak'
  package(s) announced via the DSA-4830-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Simon McVittie discovered a bug in the flatpak-portal service that can
allow sandboxed applications to execute arbitrary code on the host system
(a sandbox escape).

The Flatpak portal D-Bus service (flatpak-portal, also known by its
D-Bus service name org.freedesktop.portal.Flatpak) allows apps in a
Flatpak sandbox to launch their own subprocesses in a new sandbox
instance, either with the same security settings as the caller or
with more restrictive security settings. For example, this is used in
Flatpak-packaged web browsers such as Chromium to launch subprocesses
that will process untrusted web content, and give those subprocesses a
more restrictive sandbox than the browser itself.

In vulnerable versions, the Flatpak portal service passes caller-specified
environment variables to non-sandboxed processes on the host system,
and in particular to the flatpak run command that is used to launch the
new sandbox instance. A malicious or compromised Flatpak app could set
environment variables that are trusted by the flatpak run command, and
use them to execute arbitrary code that is not in a sandbox.");

  script_tag(name:"affected", value:"'flatpak' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), this problem has been fixed in
version 1.2.5-0+deb10u2.

We recommend that you upgrade your flatpak packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"flatpak", ver:"1.2.5-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"flatpak-tests", ver:"1.2.5-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-flatpak-1.0", ver:"1.2.5-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libflatpak-dev", ver:"1.2.5-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libflatpak-doc", ver:"1.2.5-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libflatpak0", ver:"1.2.5-0+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
