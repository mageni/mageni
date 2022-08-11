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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0408");
  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-5501", "CVE-2016-5538", "CVE-2016-5605", "CVE-2016-5608", "CVE-2016-5610", "CVE-2016-5611", "CVE-2016-5613", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6305", "CVE-2016-6306", "CVE-2016-6307", "CVE-2016-6308", "CVE-2016-6309", "CVE-2016-7052");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2016-0408)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0408");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0408.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19213");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");
  script_xref(name:"URL", value:"https://www.virtualbox.org/wiki/Changelog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) announced via the MGASA-2016-0408 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides virtualbox 5.1.10 maintenance release and resolves
at least the following security issues:

OpenSSL through 1.0.2h incorrectly uses pointer arithmetic for heap-buffer
boundary checks, which might allow remote attackers to cause a denial of
service (integer overflow and application crash) or possibly have
unspecified other impact by leveraging unexpected malloc behavior, related
to s3_srvr.c, ssl_sess.c, and t1_lib.c (CVE-2016-2177).

The dsa_sign_setup function in crypto/dsa/dsa_ossl.c in OpenSSL through
1.0.2h does not properly ensure the use of constant-time operations, which
makes it easier for local users to discover a DSA private key via a timing
side-channel attack (CVE-2016-2178).

The DTLS implementation in OpenSSL before 1.1.0 does not properly restrict
the lifetime of queue entries associated with unused out-of-order messages,
which allows remote attackers to cause a denial of service (memory
consumption) by maintaining many crafted DTLS sessions simultaneously,
related to d1_lib.c, statem_dtls.c, statem_lib.c, and statem_srvr.c
(CVE-2016-2179).

The TS_OBJ_print_bio function in crypto/ts/ts_lib.c in the X.509 Public Key
Infrastructure Time-Stamp Protocol (TSP) implementation in OpenSSL through
1.0.2h allows remote attackers to cause a denial of service (out-of-bounds
read and application crash) via a crafted time-stamp file that is mishandled
by the 'openssl ts' command (CVE-2016-2180).

The Anti-Replay feature in the DTLS implementation in OpenSSL before 1.1.0
mishandles early use of a new epoch number in conjunction with a large
sequence number, which allows remote attackers to cause a denial of service
(false-positive packet drops) via spoofed DTLS records, related to
rec_layer_d1.c and ssl3_record.c (CVE-2016-2181).

The Anti-Replay feature in the DTLS implementation in OpenSSL before 1.1.0
mishandles early use of a new epoch number in conjunction with a large
sequence number, which allows remote attackers to cause a denial of service
(false-positive packet drops) via spoofed DTLS records, related to
rec_layer_d1.c and ssl3_record.c (CVE-2016-2182).

The DES and Triple DES ciphers, as used in the TLS, SSH, and IPSec protocols
and other protocols and products, have a birthday bound of approximately
four billion blocks, which makes it easier for remote attackers to obtain
cleartext data via a birthday attack against a long-duration encrypted
session, as demonstrated by an HTTPS session using Triple DES in CBC mode,
aka a 'Sweet32' attack (CVE-2016-2183).

Unspecified vulnerability in the Oracle VM VirtualBox component before
5.0.28 and 5.1.x before 5.1.8 in Oracle Virtualization allows local users
to affect confidentiality, integrity, and availability via vectors related
to Core, a different vulnerability than CVE-2016-5538 (CVE-2016-5501).

Unspecified vulnerability in the Oracle VM VirtualBox component before
5.0.28 and 5.1.x before ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kmod-vboxadditions, kmod-virtualbox, virtualbox' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-vboxadditions", rpm:"dkms-vboxadditions~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dkms-virtualbox", rpm:"dkms-virtualbox~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.4.32-desktop-1.mga5", rpm:"vboxadditions-kernel-4.4.32-desktop-1.mga5~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.4.32-desktop586-1.mga5", rpm:"vboxadditions-kernel-4.4.32-desktop586-1.mga5~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-4.4.32-server-1.mga5", rpm:"vboxadditions-kernel-4.4.32-server-1.mga5~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-doc", rpm:"virtualbox-doc~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-additions", rpm:"virtualbox-guest-additions~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.4.32-desktop-1.mga5", rpm:"virtualbox-kernel-4.4.32-desktop-1.mga5~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.4.32-desktop586-1.mga5", rpm:"virtualbox-kernel-4.4.32-desktop586-1.mga5~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-4.4.32-server-1.mga5", rpm:"virtualbox-kernel-4.4.32-server-1.mga5~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-driver-video-vboxvideo", rpm:"x11-driver-video-vboxvideo~5.1.10~1.1.mga5", rls:"MAGEIA5"))) {
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
