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
  script_oid("1.3.6.1.4.1.25623.1.0.854675");
  script_version("2022-05-23T14:45:16+0000");
  script_cve_id("CVE-2018-14423", "CVE-2018-16376", "CVE-2020-15389", "CVE-2020-27823", "CVE-2020-8112", "CVE-2021-29338");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-23 14:45:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-31 14:26:00 +0000 (Wed, 31 Oct 2018)");
  script_tag(name:"creation_date", value:"2022-05-17 12:08:25 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for openjpeg (SUSE-SU-2022:1296-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1296-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TBRPZKOZUNORV3ZNXLKMNUZ2AUMPJ4Y6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg'
  package(s) announced via the SUSE-SU-2022:1296-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openjpeg fixes the following issues:

  - CVE-2018-14423: Fixed division-by-zero vulnerabilities in the functions
       pi_next_pcrl, pi_next_cprl, and pi_next_rpcl in lib/openjp3d/pi.c
       (bsc#1102016).

  - CVE-2018-16376: Fixed heap-based buffer overflow function
       t2_encode_packet in lib/openmj2/t2.c (bsc#1106881).

  - CVE-2020-8112: Fixed a heap buffer overflow in
       opj_t1_clbl_decode_processor in openjp2/t1.c (bsc#1162090).

  - CVE-2020-15389: Fixed a use-after-free if a mix of valid and invalid
       files in a directory operated on by the decompressor (bsc#1173578).

  - CVE-2020-27823: Fixed a heap buffer over-write in
       opj_tcd_dc_level_shift_encode() (bsc#1180457),

  - CVE-2021-29338: Fixed an integer Overflow allows remote attackers to
       crash the application (bsc#1184774).");

  script_tag(name:"affected", value:"'openjpeg' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg1", rpm:"libopenjpeg1~1.5.2~150000.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg1-debuginfo", rpm:"libopenjpeg1-debuginfo~1.5.2~150000.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg", rpm:"openjpeg~1.5.2~150000.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-debuginfo", rpm:"openjpeg-debuginfo~1.5.2~150000.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-debugsource", rpm:"openjpeg-debugsource~1.5.2~150000.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-devel", rpm:"openjpeg-devel~1.5.2~150000.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg1-32bit", rpm:"libopenjpeg1-32bit~1.5.2~150000.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg1-32bit-debuginfo", rpm:"libopenjpeg1-32bit-debuginfo~1.5.2~150000.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-devel-32bit", rpm:"openjpeg-devel-32bit~1.5.2~150000.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg1", rpm:"libopenjpeg1~1.5.2~150000.4.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg1-debuginfo", rpm:"libopenjpeg1-debuginfo~1.5.2~150000.4.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg", rpm:"openjpeg~1.5.2~150000.4.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-debuginfo", rpm:"openjpeg-debuginfo~1.5.2~150000.4.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-debugsource", rpm:"openjpeg-debugsource~1.5.2~150000.4.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-devel", rpm:"openjpeg-devel~1.5.2~150000.4.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg1-32bit", rpm:"libopenjpeg1-32bit~1.5.2~150000.4.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg1-32bit-debuginfo", rpm:"libopenjpeg1-32bit-debuginfo~1.5.2~150000.4.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg-devel-32bit", rpm:"openjpeg-devel-32bit~1.5.2~150000.4.5.1", rls:"openSUSELeap15.3"))) {
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