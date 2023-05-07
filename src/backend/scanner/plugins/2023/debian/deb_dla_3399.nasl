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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3399");
  script_cve_id("CVE-2019-10224", "CVE-2019-14824", "CVE-2019-3883", "CVE-2021-3514", "CVE-2021-3652", "CVE-2021-4091", "CVE-2022-0918", "CVE-2022-0996", "CVE-2022-2850");
  script_tag(name:"creation_date", value:"2023-04-25 04:25:16 +0000 (Tue, 25 Apr 2023)");
  script_version("2023-04-25T10:19:16+0000");
  script_tag(name:"last_modification", value:"2023-04-25 10:19:16 +0000 (Tue, 25 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 19:54:00 +0000 (Mon, 28 Nov 2022)");

  script_name("Debian: Security Advisory (DLA-3399)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3399");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3399");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/389-ds-base");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian '389-ds-base' package(s) announced via the DLA-3399 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in 389-ds-base: an open source LDAP server for Linux.

CVE-2019-3883

SSL/TLS requests do not enforce ioblocktimeout limit, leading to DoS vulnerability by hanging all workers with hanging LDAP requests.

CVE-2019-10224

The vulnerability may disclose sensitive information, such as the Directory Manager password, when the dscreate and dsconf commands are executed in verbose mode. An attacker who can view the screen or capture the terminal standard error output can exploit thisvulnerability to obtain confidential information.

CVE-2019-14824

The deref plugin of 389-ds-base has a vulnerability that enables it to disclose attribute values using the search permission. In certain setups, an authenticated attacker can exploit this flaw to access confidential attributes, including password hashes.

CVE-2021-3514

If a sync_repl client is used, an authenticated attacker can trigger a crash by exploiting a specially crafted query that leads to a NULL pointer dereference.

CVE-2021-3652

Importing an asterisk as password hashes enables successful authentication with any password, allowing attackers to access accounts with disabled passwords.

CVE-2021-4091

A double free was found in the way 389-ds-base handles virtual attributes context in persistent searches. An attacker could send a series of search requests, forcing the server to behave unexpectedly, and crash.

CVE-2022-0918

An unauthenticated attacker with network access to the LDAP port can cause a denial of service. The denial of service is triggered by a single message sent over a TCP connection, no bind or other authentication is required. The message triggers a segmentation fault that results in slapd crashing.

CVE-2022-0996

Expired password was still allowed to access the database. A user whose password was expired was still allowed to access the database as if the password was not expired. Once a password is expired, and grace logins have been used up, the account is basically supposed to be locked out and should not be allowed to perform any privileged action.

CVE-2022-2850

The vulnerability in content synchronization plugin enables an authenticated attacker to trigger a denial of service via a crafted query through a NULL pointer dereference.

For Debian 10 buster, these problems have been fixed in version 1.4.0.21-1+deb10u1.

We recommend that you upgrade your 389-ds-base packages.

For the detailed security status of 389-ds-base please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"389-ds-base-dev", ver:"1.4.0.21-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"389-ds-base-legacy-tools", ver:"1.4.0.21-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"389-ds-base-libs", ver:"1.4.0.21-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"389-ds-base", ver:"1.4.0.21-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"389-ds", ver:"1.4.0.21-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cockpit-389-ds", ver:"1.4.0.21-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-lib389", ver:"1.4.0.21-1+deb10u1", rls:"DEB10"))) {
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
