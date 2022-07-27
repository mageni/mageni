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
  script_oid("1.3.6.1.4.1.25623.1.0.854636");
  script_version("2022-05-23T14:45:16+0000");
  script_cve_id("CVE-2018-14423", "CVE-2018-16375", "CVE-2018-16376", "CVE-2018-20845", "CVE-2018-5727", "CVE-2018-5785", "CVE-2018-6616", "CVE-2020-15389", "CVE-2020-27823", "CVE-2020-6851", "CVE-2020-8112", "CVE-2021-29338", "CVE-2022-1122");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-23 14:45:16 +0000 (Mon, 23 May 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-26 12:50:00 +0000 (Tue, 26 Jan 2021)");
  script_tag(name:"creation_date", value:"2022-05-17 12:06:24 +0000 (Tue, 17 May 2022)");
  script_name("openSUSE: Security Advisory for openjpeg2 (SUSE-SU-2022:1252-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1252-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/662Q4K3MTGYRNK4HPTROD3ZFI3H2D2QA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the SUSE-SU-2022:1252-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openjpeg2 fixes the following issues:

  - CVE-2018-5727: Fixed integer overflow vulnerability in
       theopj_t1_encode_cblks function (bsc#1076314).

  - CVE-2018-5785: Fixed integer overflow caused by an out-of-bounds
       leftshift in the opj_j2k_setup_encoder function (bsc#1076967).

  - CVE-2018-6616: Fixed excessive iteration in the opj_t1_encode_cblks
       function of openjp2/t1.c (bsc#1079845).

  - CVE-2018-14423: Fixed division-by-zero vulnerabilities in the functions
       pi_next_pcrl, pi_next_cprl, and pi_next_rpcl in lib/openjp3d/pi.c
       (bsc#1102016).

  - CVE-2018-16375: Fixed missing checks for header_info.height and
       header_info.width in the function pnmtoimage in bin/jpwl/convert.c
       (bsc#1106882).

  - CVE-2018-16376: Fixed heap-based buffer overflow function
       t2_encode_packet in lib/openmj2/t2.c (bsc#1106881).

  - CVE-2018-20845: Fixed division-by-zero in the functions pi_next_pcrl,
       pi_next_cprl, and pi_next_rpcl in openmj2/pi.ci (bsc#1140130).

  - CVE-2020-6851: Fixed heap-based buffer overflow in
       opj_t1_clbl_decode_processor (bsc#1160782).

  - CVE-2020-8112: Fixed heap-based buffer overflow in
       opj_t1_clbl_decode_processor in openjp2/t1.c (bsc#1162090).

  - CVE-2020-15389: Fixed use-after-free if t a mix of valid and invalid
       files in a directory operated on by the decompressor (bsc#1173578).

  - CVE-2020-27823: Fixed heap buffer over-write in
       opj_tcd_dc_level_shift_encode() (bsc#1180457).

  - CVE-2021-29338: Fixed integer overflow that allows remote attackers to
       crash the application (bsc#1184774).

  - CVE-2022-1122: Fixed segmentation fault in opj2_decompress due to
       uninitialized pointer (bsc#1197738).");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.3.0~150000.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.3.0~150000.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.3.0~150000.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-32bit", rpm:"libopenjp2-7-32bit~2.3.0~150000.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-32bit-debuginfo", rpm:"libopenjp2-7-32bit-debuginfo~2.3.0~150000.3.5.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.3.0~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.3.0~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.3.0~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-32bit", rpm:"libopenjp2-7-32bit~2.3.0~150000.3.5.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-32bit-debuginfo", rpm:"libopenjp2-7-32bit-debuginfo~2.3.0~150000.3.5.1", rls:"openSUSELeap15.3"))) {
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