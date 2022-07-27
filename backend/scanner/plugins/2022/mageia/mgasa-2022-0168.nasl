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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0168");
  script_cve_id("CVE-2022-21712", "CVE-2022-21716");
  script_tag(name:"creation_date", value:"2022-05-19 07:28:20 +0000 (Thu, 19 May 2022)");
  script_version("2022-05-19T07:28:20+0000");
  script_tag(name:"last_modification", value:"2022-05-19 09:49:33 +0000 (Thu, 19 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 17:45:00 +0000 (Thu, 10 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0168");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0168.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30067");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-February/010263.html");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2927");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/233XDDM6URC3DPBBAKQV2AZQY6TBXJRV/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2938");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5354-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HJFVJUKPT7GYOWBWGQSIVM3OEHKOEVVJ/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-automat, python-incremental, python-twisted' package(s) announced via the MGASA-2022-0168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-21712: It was discovered that Twisted incorrectly filtered HTTP
headers when clients are being redirected to another origin. A remote
attacker could use this issue to obtain sensitive information.
CVE-2022-21716: It was discovered that Twisted incorrectly processed SSH
handshake data on connection establishments. A remote attacker could use
this issue to cause Twisted to crash, resulting in a denial of service.

GHSA-rv6r-3f5q-9rgx
The Twisted SSH client and server implementation naively accepted an
infinite amount of data for the peer's SSH version identifier.

GHSA-c2jg-hw38-jrqq and CVE-2022-24801
The Twisted Web HTTP 1.1 server, located in the twisted.web.http module,
parsed several HTTP request constructs more leniently than permitted by
RFC 7230

GHSA-92x2-jw7w-xvvx: twisted.web.client.getPage,
twisted.web.client.downladPage, and the associated implementation classes
(HTTPPageGetter, HTTPPageDownloader, HTTPClientFactory, HTTPDownloader)
have been removed because they do not segregate cookies by domain. They
were deprecated in Twisted 16.7.0 in favor of twisted.web.client.Agent.");

  script_tag(name:"affected", value:"'python-automat, python-incremental, python-twisted' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"python-automat", rpm:"python-automat~0.8.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-incremental", rpm:"python-incremental~21.3.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-twisted", rpm:"python-twisted~22.4.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-automat", rpm:"python3-automat~0.8.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-incremental", rpm:"python3-incremental~21.3.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-twisted+tls", rpm:"python3-twisted+tls~22.4.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-twisted", rpm:"python3-twisted~22.4.0~1.mga8", rls:"MAGEIA8"))) {
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
