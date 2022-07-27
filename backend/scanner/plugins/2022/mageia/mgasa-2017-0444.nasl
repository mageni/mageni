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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0444");
  script_cve_id("CVE-2017-8819", "CVE-2017-8820", "CVE-2017-8821", "CVE-2017-8822", "CVE-2017-8823");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-21 18:01:00 +0000 (Thu, 21 Dec 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0444)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0444");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0444.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22108");
  script_xref(name:"URL", value:"https://blog.torproject.org/new-stable-tor-releases-security-fixes-0319-03013-02914-02817-02516");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tor, tor' package(s) announced via the MGASA-2017-0444 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When checking for replays in the INTRODUCE1 cell data for a (legacy) onion
service, Tor didn't correctly detect replays in the RSA- encrypted part of
the cell. It was previously checking for replays on the entire cell, but
those can be circumvented due to the malleability of Tor's legacy hybrid
encryption. This can lead to a traffic confirmation attack (CVE-2017-8819).

Denial of service issue where an attacker could crash a directory authority
using a malformed router descriptor (CVE-2017-8820).

Denial of service bug where an attacker could use a malformed directory
object to cause a Tor instance to pause while OpenSSL would try to read a
passphrase from the terminal (CVE-2017-8821).

When running as a relay, Tor could build a path through itself, especially
when it lost the version of its descriptor appearing in the consensus. When
running as a relay, it could also choose itself as a guard (CVE-2017-8822).

Use-after-free error that could crash v2 Tor onion services when they failed
to open circuits while expiring introduction points (CVE-2017-8823).");

  script_tag(name:"affected", value:"'tor, tor' package(s) on Mageia 5, Mageia 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.2.8.17~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.2.9.14~1.mga6", rls:"MAGEIA6"))) {
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
