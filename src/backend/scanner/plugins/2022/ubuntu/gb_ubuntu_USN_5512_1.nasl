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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5512.1");
  script_cve_id("CVE-2022-1834", "CVE-2022-2200", "CVE-2022-2226", "CVE-2022-31736", "CVE-2022-31737", "CVE-2022-31738", "CVE-2022-31740", "CVE-2022-31741", "CVE-2022-31742", "CVE-2022-31744", "CVE-2022-31747", "CVE-2022-34468", "CVE-2022-34470", "CVE-2022-34472", "CVE-2022-34479", "CVE-2022-34481", "CVE-2022-34484");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5512-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.10|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5512-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5512-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-5512-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked into opening a specially crafted website in a browsing context, an
attacker could potentially exploit these to cause a denial of service,
obtain sensitive information, spoof the UI, bypass CSP restrictions, or
execute arbitrary code. (CVE-2022-2200, CVE-2022-31736, CVE-2022-31737,
CVE-2022-31738, CVE-2022-31740, CVE-2022-31741, CVE-2022-31742,
CVE-2022-31744, CVE-2022-31747, CVE-2022-34468, CVE-2022-34470,
CVE-2022-34479, CVE-2022-34481, CVE-2022-34484)

It was discovered that an unavailable PAC file caused OCSP requests to
be blocked, resulting in incorrect error pages being displayed.
(CVE-2022-34472)

It was discovered that the Braille space character could be used to
cause Thunderbird to display the wrong sender address for signed messages.
An attacker could potentially exploit this to trick the user into
believing a message had been sent from somebody they trusted.
(CVE-2022-1834)

It was discovered that Thunderbird would consider an email with a
mismatched OpenPGP signature date as valid. An attacker could potentially
exploit this by replaying an older message in order to trick the user into
believing that the statements in the message are current. (CVE-2022-2226)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:91.11.0+build2-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:91.11.0+build2-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:91.11.0+build2-0ubuntu0.21.10.1", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:91.11.0+build2-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
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
