# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4634.1");
  script_cve_id("CVE-2019-17540", "CVE-2020-21679", "CVE-2021-20176", "CVE-2021-20224", "CVE-2021-20241", "CVE-2021-20243", "CVE-2021-20244", "CVE-2021-20246", "CVE-2021-20309", "CVE-2021-20311", "CVE-2021-20312", "CVE-2021-20313", "CVE-2021-3574", "CVE-2022-0284", "CVE-2022-2719", "CVE-2022-28463", "CVE-2022-32545", "CVE-2022-32546", "CVE-2022-32547", "CVE-2022-44267", "CVE-2022-44268", "CVE-2023-1289", "CVE-2023-34151", "CVE-2023-3745", "CVE-2023-5341");
  script_tag(name:"creation_date", value:"2023-12-04 04:20:18 +0000 (Mon, 04 Dec 2023)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-17 19:53:24 +0000 (Mon, 17 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4634-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4634-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234634-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2023:4634-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:
Security issues:

CVE-2023-5341: Fixed a heap use-after-free in coders/bmp.c. (bsc#1215939)
CVE-2020-21679: Fixed a buffer overflow in WritePCXImage function in pcx.c which may allow a remote attackers to cause a denial of service. (bsc#1214578)
CVE-2023-3745: Fixed heap out of bounds read in PushCharPixel() in quantum-private.h (bsc#1213624).
CVE-2023-34151: Fixed an undefined behavior issue due to floating point truncation (bsc#1211791).
CVE-2023-1289: Fixed segmentation fault and possible DoS via specially crafted SVG. (bsc#1209141)
CVE-2022-44268: Fixed arbitrary file disclosure when parsing a PNG image (bsc#1207983).
CVE-2022-44267: Fixed a denial of service when parsing a PNG image (bsc#1207982).
CVE-2022-32547: Fixed a load of misaligned address at MagickCore/property.c. (bsc#1200387)
CVE-2022-32546: Fixed an outside the range of representable values of type. (bsc#1200389)
CVE-2022-32545: Fixed an outside the range of representable values of type. (bsc#1200388)
CVE-2022-28463: Fixed buffer overflow in coders/cin.c (bsc#1199350).
CVE-2022-2719: Fixed a reachable assertion that could lead to denial of service via a crafted file (bsc#1202250).
CVE-2022-0284: Fixed heap buffer overread in GetPixelAlpha() in MagickCore/pixel-accessor.h (bsc#1195563).
CVE-2021-3574: Fixed memory leaks with convert command (bsc#1203212).
CVE-2021-20313: Cipher leak when the calculating signatures in TransformSignatureof MagickCore/signature.c (bsc#1184628)
CVE-2021-20312: Integer overflow in WriteTHUMBNAILImage of coders/thumbnail.c (bsc#1184627)
CVE-2021-20311: Division by zero in sRGBTransformImage() in MagickCore/colorspace.c (bsc#1184626)
CVE-2021-20309: Division by zero in WaveImage() of MagickCore/visual-effects. (bsc#1184624)
CVE-2021-20246: Division by zero in ScaleResampleFilter in MagickCore/resample.c (bsc#1182337).
CVE-2021-20244: Division by zero in ImplodeImage in MagickCore/visual-effects.c (bsc#1182325).
CVE-2021-20243: Division by zero in GetResizeFilterWeight in MagickCore/resize.c (bsc#1182336).
CVE-2021-20241: Division by zero in WriteJP2Image() in coders/jp2.c (bsc#1182335).
CVE-2021-20224: Fixed an integer overflow that could be triggered via a crafted file (bsc#1202800).
CVE-2021-20176: Fixed an issue where processing a crafted file could lead to division by zero (bsc#1181836).
CVE-2019-17540: Fixed heap-based buffer overflow in ReadPSInfo in coders/ps.c. (bsc#1153866)

Bugfixes:

Use png_get_eXIf_1 when available (bsc#1197147).");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE CaaS Platform 4.0, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-SUSE", rpm:"ImageMagick-config-7-SUSE~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-config-7-upstream", rpm:"ImageMagick-config-7-upstream~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI4", rpm:"libMagick++-7_Q16HDRI4~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-7_Q16HDRI4-debuginfo", rpm:"libMagick++-7_Q16HDRI4-debuginfo~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI6", rpm:"libMagickCore-7_Q16HDRI6~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore-7_Q16HDRI6-debuginfo", rpm:"libMagickCore-7_Q16HDRI6-debuginfo~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI6", rpm:"libMagickWand-7_Q16HDRI6~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickWand-7_Q16HDRI6-debuginfo", rpm:"libMagickWand-7_Q16HDRI6-debuginfo~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PerlMagick-debuginfo", rpm:"perl-PerlMagick-debuginfo~7.0.7.34~150000.3.123.1", rls:"SLES15.0SP1"))) {
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
