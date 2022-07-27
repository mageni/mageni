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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0151");
  script_cve_id("CVE-2018-7320", "CVE-2018-7321", "CVE-2018-7322", "CVE-2018-7323", "CVE-2018-7324", "CVE-2018-7325", "CVE-2018-7326", "CVE-2018-7327", "CVE-2018-7328", "CVE-2018-7329", "CVE-2018-7330", "CVE-2018-7331", "CVE-2018-7332", "CVE-2018-7333", "CVE-2018-7334", "CVE-2018-7335", "CVE-2018-7336", "CVE-2018-7417", "CVE-2018-7418", "CVE-2018-7419", "CVE-2018-7420", "CVE-2018-9256", "CVE-2018-9259", "CVE-2018-9260", "CVE-2018-9261", "CVE-2018-9262", "CVE-2018-9263", "CVE-2018-9264", "CVE-2018-9265", "CVE-2018-9266", "CVE-2018-9267", "CVE-2018-9268", "CVE-2018-9269", "CVE-2018-9270", "CVE-2018-9271", "CVE-2018-9272", "CVE-2018-9273", "CVE-2018-9274");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0151)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0151");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0151.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22643");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-05.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-06.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-07.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-09.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-10.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-11.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-12.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-13.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-14.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-15.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-16.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-17.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-18.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-19.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-20.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2018-23.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.13.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.14.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20180223.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/news/20180403.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-04/msg00015.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the MGASA-2018-0151 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SIGCOMP dissector could crash (CVE-2018-7320).

Multiple dissectors could go into large infinite loops. All ASN.1 BER
dissectors, along with the DICOM, DMP, LLTD, OpenFlow, RELOAD, RPCoRDMA,
RPKI-Router, S7COMM, SCCP, Thread, Thrift, USB, and WCCP dissectors were
susceptible (CVE-2018-7321,CVE-2018-7322, CVE-2018-7323, CVE-2018-7324,
CVE-2018-7325, CVE-2018-7326, CVE-2018-7327, CVE-2018-7328,
CVE-2018-7329, CVE-2018-7330, CVE-2018-7331, CVE-2018-7332,
CVE-2018-7333).

The UMTS MAC dissector could crash (CVE-2018-7334).

The IEEE 802.11 dissector could crash (CVE-2018-7335)

The FCP dissector could crash (CVE-2018-7336).

The IPMI dissector could crash (CVE-2018-7417).

The SIGCOMP dissector could crash (CVE-2018-7418).

The NBAP disssector could crash (CVE-2018-7419).

The pcapng file parser could crash (CVE-2018-7420).

The LWAPP dissector could crash (CVE-2018-9256).

The MP4 dissector could crash (CVE-2018-9259).

The IEEE 802.15.4 dissector could crash (CVE-2018-9260).

The NBAP dissector could crash (CVE-2018-9261).

The VLAN dissector could crash (CVE-2018-9262).

The Kerberos dissector could crash (CVE-2018-9263).

The ADB dissector could crash (CVE-2018-9264).

Memory leaks in multiple dissectors (CVE-2018-9265, CVE-2018-9266,
CVE-2018-9267, CVE-2018-9268, CVE-2018-9269, CVE-2018-9270,
CVE-2018-9271, CVE-2018-9272, CVE-2018-9273, CVE-2018-9274).");

  script_tag(name:"affected", value:"'wireshark' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wireshark8", rpm:"lib64wireshark8~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wiretap6", rpm:"lib64wiretap6~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wscodecs1", rpm:"lib64wscodecs1~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wsutil7", rpm:"lib64wsutil7~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark8", rpm:"libwireshark8~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap6", rpm:"libwiretap6~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil7", rpm:"libwsutil7~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tshark", rpm:"tshark~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.2.14~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~2.2.14~1.mga6", rls:"MAGEIA6"))) {
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
