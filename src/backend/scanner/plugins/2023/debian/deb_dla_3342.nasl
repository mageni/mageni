# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893342");
  script_cve_id("CVE-2022-41859", "CVE-2022-41860", "CVE-2022-41861");
  script_tag(name:"creation_date", value:"2023-02-25 02:00:16 +0000 (Sat, 25 Feb 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-24 19:53:00 +0000 (Tue, 24 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-3342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3342");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3342");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/freeradius");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freeradius' package(s) announced via the DLA-3342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several flaws were found in freeradius, a high-performance and highly configurable RADIUS server.

CVE-2022-41859

In freeradius, the EAP-PWD function compute_password_element() leaks information about the password which allows an attacker to substantially reduce the size of an offline dictionary attack.

CVE-2022-41860

In freeradius, when an EAP-SIM supplicant sends an unknown SIM option, the server will try to look that option up in the internal dictionaries. This lookup will fail, but the SIM code will not check for that failure. Instead, it will dereference a NULL pointer, and cause the server to crash.

CVE-2022-41861

A malicious RADIUS client or home server can send a malformed attribute which can cause the server to crash.

For Debian 10 buster, these problems have been fixed in version 3.0.17+dfsg-1.1+deb10u2.

We recommend that you upgrade your freeradius packages.

For the detailed security status of freeradius please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'freeradius' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-common", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-config", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-dhcp", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-iodbc", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-krb5", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-ldap", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-memcached", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-mysql", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-postgresql", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-python2", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-redis", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-rest", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-utils", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius-yubikey", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"freeradius", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeradius-dev", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libfreeradius3", ver:"3.0.17+dfsg-1.1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
