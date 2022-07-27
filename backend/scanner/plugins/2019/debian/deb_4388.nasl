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
  script_oid("1.3.6.1.4.1.25623.1.0.704388");
  script_version("2019-04-02T06:16:35+0000");
  script_cve_id("CVE-2018-12546", "CVE-2018-12550", "CVE-2018-12551");
  script_name("Debian Security Advisory DSA 4388-1 (mosquitto - security update)");
  script_tag(name:"last_modification", value:"2019-04-02 06:16:35 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-10 00:00:00 +0100 (Sun, 10 Feb 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4388.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"mosquitto on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 1.4.10-3+deb9u3.

We recommend that you upgrade your mosquitto packages.

For the detailed security status of mosquitto please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mosquitto");
  script_tag(name:"summary", value:"Three vulnerabilities were discovered in the Mosquitto MQTT broker, which
could result in authentication bypass. Please
for additional
information.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  script_xref(name:"URL", value:"https://mosquitto.org/blog/2019/02/version-1-5-6-released/");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libmosquitto-dev", ver:"1.4.10-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmosquitto1", ver:"1.4.10-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmosquitto1-dbg", ver:"1.4.10-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmosquittopp-dev", ver:"1.4.10-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmosquittopp1", ver:"1.4.10-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libmosquittopp1-dbg", ver:"1.4.10-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mosquitto", ver:"1.4.10-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mosquitto-clients", ver:"1.4.10-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mosquitto-dbg", ver:"1.4.10-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mosquitto-dev", ver:"1.4.10-3+deb9u3", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}