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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0258");
  script_cve_id("CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-26139", "CVE-2020-26141", "CVE-2020-26145", "CVE-2020-26147", "CVE-2021-28691", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-38208");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0258)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0258");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0258.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29107");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.42");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.10.43");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-374.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus, kernel-linus' package(s) announced via the MGASA-2021-0258 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.10.43 and fixes at least
the following security issues:

The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and
WPA3) and Wired Equivalent Privacy (WEP) doesn't require that received
fragments be cleared from memory after (re)connecting to a network. Under
the right circumstances, when another device sends fragmented frames
encrypted using WEP, CCMP, or GCMP, this can be abused to inject arbitrary
network packets and/or exfiltrate user data (CVE-2020-24586).

The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and
WPA3) and Wired Equivalent Privacy (WEP) doesn't require that all fragments
of a frame are encrypted under the same key. An adversary can abuse this to
decrypt selected fragments when another device sends fragmented frames and
the WEP, CCMP, or GCMP encryption key is periodically renewed
(CVE-2020-24587).

The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and
WPA3) and Wired Equivalent Privacy (WEP) doesn't require that the A-MSDU
flag in the plaintext QoS header field is authenticated. Against devices
that support receiving non-SSP A-MSDU frames (which is mandatory as part
of 802.11n), an adversary can abuse this to inject arbitrary network
packets (CVE-2020-24588).

An issue was discovered in the kernel. An Access Point (AP) forwards EAPOL
frames to other clients even though the sender has not yet successfully
authenticated to the AP. This might be abused in projected Wi-Fi networks
to launch denial-of-service attacks against connected clients and makes
it easier to exploit other vulnerabilities in connected clients
(CVE-2020-26139).

An issue was discovered in the kernel ath10k driver. The Wi-Fi
implementation does not verify the Message Integrity Check (authenticity)
of fragmented TKIP frames. An adversary can abuse this to inject and
possibly decrypt packets in WPA or WPA2 networks that support the TKIP
data-confidentiality protocol (CVE-2020-26141).

An issue was discovered in the kernel ath10k driver. The WEP, WPA, WPA2,
and WPA3 implementations accept second (or subsequent) broadcast fragments
even when sent in plaintext and process them as full unfragmented frames.
An adversary can abuse this to inject arbitrary network packets independent
of the network configuration (CVE-2020-26145).

An issue was discovered in the Linux kernel 5.8.9. The WEP, WPA, WPA2, and
WPA3 implementations reassemble fragments even though some of them were
sent in plaintext. This vulnerability can be abused to inject packets and/
or exfiltrate selected fragments when another device sends fragmented
frames and the WEP, CCMP, or GCMP data-confidentiality protocol is used
(CVE-2020-26147).

A double-free memory corruption in the Linux kernel HCI device
initialization subsystem was found in the way user attach malicious HCI
TTY Bluetooth device. A local user could use this flaw ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-linus, kernel-linus' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.10.43-1.mga7", rpm:"kernel-linus-5.10.43-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.10.43~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.10.43-1.mga7", rpm:"kernel-linus-devel-5.10.43-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.10.43~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.10.43~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.10.43~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.10.43-1.mga7", rpm:"kernel-linus-source-5.10.43-1.mga7~1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.10.43~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.10.43-1.mga8", rpm:"kernel-linus-5.10.43-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.10.43~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.10.43-1.mga8", rpm:"kernel-linus-devel-5.10.43-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.10.43~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.10.43~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.10.43~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.10.43-1.mga8", rpm:"kernel-linus-source-5.10.43-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.10.43~1.mga8", rls:"MAGEIA8"))) {
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
