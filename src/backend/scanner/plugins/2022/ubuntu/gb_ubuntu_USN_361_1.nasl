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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.361.1");
  script_cve_id("CVE-2006-2788", "CVE-2006-3805", "CVE-2006-3806", "CVE-2006-3807", "CVE-2006-3808", "CVE-2006-3809", "CVE-2006-3811", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4568", "CVE-2006-4570", "CVE-2006-4571");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-361-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.04|5\.10)");

  script_xref(name:"Advisory-ID", value:"USN-361-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-361-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla' package(s) announced via the USN-361-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious URL. (CVE-2006-2788, CVE-2006-3805, CVE-2006-3806,
CVE-2006-3807, CVE-2006-3809, CVE-2006-3811, CVE-2006-4565,
CVE-2006-4568, CVE-2006-4571)

A bug was found in the script handler for automatic proxy
configuration. A malicious proxy could send scripts which could
execute arbitrary code with the user's privileges. (CVE-2006-3808)

The NSS library did not sufficiently check the padding of PKCS #1 v1.5
signatures if the exponent of the public key is 3 (which is widely
used for CAs). This could be exploited to forge valid signatures
without the need of the secret key. (CVE-2006-4340)

Georgi Guninski discovered that even with JavaScript disabled, a
malicious email could still execute JavaScript when the message is
viewed, replied to, or forwarded by putting the script in a remote XBL
file loaded by the message. (CVE-2006-4570)");

  script_tag(name:"affected", value:"'mozilla' package(s) on Ubuntu 5.04, Ubuntu 5.10.");

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

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4", ver:"2:1.7.13-0ubuntu05.04.2", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:1.7.13-0ubuntu05.04.2", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-browser", ver:"2:1.7.13-0ubuntu05.04.2", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-mailnews", ver:"2:1.7.13-0ubuntu05.04.2", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-psm", ver:"2:1.7.13-0ubuntu05.04.2", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4", ver:"2:1.7.13-0ubuntu5.10.2", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:1.7.13-0ubuntu5.10.2", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-browser", ver:"2:1.7.13-0ubuntu5.10.2", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-mailnews", ver:"2:1.7.13-0ubuntu5.10.2", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-psm", ver:"2:1.7.13-0ubuntu5.10.2", rls:"UBUNTU5.10"))) {
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
