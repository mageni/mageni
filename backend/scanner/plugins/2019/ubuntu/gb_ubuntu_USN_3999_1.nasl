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
  script_oid("1.3.6.1.4.1.25623.1.0.844030");
  script_version("2019-06-04T07:02:10+0000");
  script_cve_id("CVE-2018-10844", "CVE-2018-10845", "CVE-2018-10846", "CVE-2019-3829", "CVE-2019-3836");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-06-04 07:02:10 +0000 (Tue, 04 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-05-31 02:00:34 +0000 (Fri, 31 May 2019)");
  script_name("Ubuntu Update for gnutls28 USN-3999-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.10|UBUNTU19\.04|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS)");

  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-May/004928.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls28'
  package(s) announced via the USN-3999-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Eyal Ronen, Kenneth G. Paterson, and Adi Shamir discovered that GnuTLS was
vulnerable to a timing side-channel attack known as the 'Lucky Thirteen'
issue. A remote attacker could possibly use this issue to perform
plaintext-recovery attacks via analysis of timing data. This issue only
affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-10844,
CVE-2018-10845, CVE-2018-10846)

Tavis Ormandy discovered that GnuTLS incorrectly handled memory when
verifying certain X.509 certificates. A remote attacker could use this
issue to cause GnuTLS to crash, resulting in a denial of service, or
possibly execute arbitrary code. This issue only affected Ubuntu 18.04 LTS,
Ubuntu 18.10, and Ubuntu 19.04. (CVE-2019-3829)

It was discovered that GnuTLS incorrectly handled certain post-handshake
messages. A remote attacker could use this issue to cause GnuTLS to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 18.10 and Ubuntu 19.04. (CVE-2019-3836)");

  script_tag(name:"affected", value:"'gnutls28' package(s) on Ubuntu 19.04, Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.6.4-2ubuntu1.2", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.6.5-2ubuntu1.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.5.18-1ubuntu1.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls30", ver:"3.4.10-4ubuntu1.5", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
