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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0446");
  script_cve_id("CVE-2021-20224", "CVE-2021-20309", "CVE-2021-20311", "CVE-2021-20312", "CVE-2021-20313", "CVE-2021-3574", "CVE-2021-4219", "CVE-2022-0284", "CVE-2022-1114", "CVE-2022-1270", "CVE-2022-2719", "CVE-2022-28463", "CVE-2022-3213", "CVE-2022-32545", "CVE-2022-32546", "CVE-2022-32547");
  script_tag(name:"creation_date", value:"2022-12-07 04:12:01 +0000 (Wed, 07 Dec 2022)");
  script_version("2022-12-07T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-12-07 10:11:17 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-30 18:14:00 +0000 (Thu, 30 Jun 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0446)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0446");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0446.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29054");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QPPJFFJWUIW3K6NB472QVFG522DWQZET/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5158-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZUE6OO6UE5NEQ2LYEJSEB2AXREVWZVMB/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3007");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/U4SLHXE2O3IXMI4KAK7QSBITGXIK6OW2/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-May/011200.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5456-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FYRR2QY5S3HG4B4EAPF6BVV54BZQPUX5/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5534-1");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-September/012065.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DQYFWVB5WL5D7BG6DWWI7RKZDHYKRQR6/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/LNVDNM4ZEIYPT3SLZHPYN7OG4CZLEXZJ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/T6VPXZJUL64MXAMQ4JA6V6TYNOXDC6SQ/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/65CCSW6TK2CGQU6OYUEHQBBH6OSPKUJP/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5736-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abydos, converseen, digikam, imagemagick, libopenshot, php-imagick, synfig, transcode, windowmaker, xine-lib1.2, zbar' package(s) announced via the MGASA-2022-0446 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in ImageMagick-7.0.11-5, where executing a
crafted file with the convert command, ASAN detects memory leaks.
(CVE-2021-3574)

A flaw was found in ImageMagick. The vulnerability occurs due to improper
use of open functions and leads to a denial of service. This flaw allows
an attacker to crash the system. (CVE-2021-4219)

An integer overflow issue was discovered in ImageMagick's
ExportIndexQuantum() function in MagickCore/quantum-export.c. Function
calls to GetPixelIndex() could result in values outside the range of
representable for the 'unsigned char'. When ImageMagick processes a
crafted pdf file, this could lead to an undefined behaviour or a crash.
(CVE-2021-20224)

A flaw was found in ImageMagick in versions before 7.0.11 and before
6.9.12, where a division by zero in WaveImage() of
MagickCore/visual-effects.c may trigger undefined behavior via a crafted
image file submitted to an application using ImageMagick. The highest
threat from this vulnerability is to system availability. (CVE-2021-20309)

A flaw was found in ImageMagick in versions before 7.0.11, where a
division by zero in sRGBTransformImage() in the MagickCore/colorspace.c
may trigger undefined behavior via a crafted image file that is submitted
by an attacker processed by an application using ImageMagick. The highest
threat from this vulnerability is to system availability. (CVE-2021-20311)

A flaw was found in ImageMagick in versions 7.0.11, where an integer
overflow in WriteTHUMBNAILImage of coders/thumbnail.c may trigger
undefined behavior via a crafted image file that is submitted by an
attacker and processed by an application using ImageMagick. The highest
threat from this vulnerability is to system availability. (CVE-2021-20312)

A flaw was found in ImageMagick in versions before 7.0.11. A potential
cipher leak when the calculate signatures in TransformSignature is
possible. The highest threat from this vulnerability is to data
confidentiality. (CVE-2021-20313)

A heap-based-buffer-over-read flaw was found in ImageMagick's
GetPixelAlpha() function of 'pixel-accessor.h'. This vulnerability is
triggered when an attacker passes a specially crafted Tagged Image File
Format (TIFF) image to convert it into a PICON file format. This issue can
potentially lead to a denial of service and information disclosure.
(CVE-2022-0284)

A heap-use-after-free flaw was found in ImageMagick's RelinquishDCMInfo()
function of dcm.c file. This vulnerability is triggered when an attacker
passes a specially crafted DICOM image file to ImageMagick for conversion,
potentially leading to information disclosure and a denial of service.
(CVE-2022-1114)

In GraphicsMagick, a heap buffer overflow was found when parsing MIFF.
(CVE-2022-1270)

In ImageMagick, a crafted file could trigger an assertion failure when a
call to WriteImages was made in MagickWand/operation.c, due to a NULL
image list. This could ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'abydos, converseen, digikam, imagemagick, libopenshot, php-imagick, synfig, transcode, windowmaker, xine-lib1.2, zbar' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"abydos", rpm:"abydos~0.2.3~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abydos", rpm:"abydos~0.2.3~4.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abydos-config", rpm:"abydos-config~0.2.3~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abydos-config", rpm:"abydos-config~0.2.3~4.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"converseen", rpm:"converseen~0.9.8.1~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"default-windowmaker-desktop", rpm:"default-windowmaker-desktop~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"digikam", rpm:"digikam~7.1.0~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.1.0.52~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.1.0.52~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.1.0.52~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.1.0.52~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.1.0.52~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.1.0.52~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.2-devel", rpm:"lib64abydos0.2-devel~0.2.3~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.2-devel", rpm:"lib64abydos0.2-devel~0.2.3~4.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.2_0", rpm:"lib64abydos0.2_0~0.2.3~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64abydos0.2_0", rpm:"lib64abydos0.2_0~0.2.3~4.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikam-devel", rpm:"lib64digikam-devel~7.1.0~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamcore7.1.0", rpm:"lib64digikamcore7.1.0~7.1.0~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamdatabase7.1.0", rpm:"lib64digikamdatabase7.1.0~7.1.0~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamgui7.1.0", rpm:"lib64digikamgui7.1.0~7.1.0~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.1.0.52~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.1.0.52~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_10", rpm:"lib64magick-7Q16HDRI_10~7.1.0.52~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_10", rpm:"lib64magick-7Q16HDRI_10~7.1.0.52~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.1.0.52~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.1.0.52~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openshot-devel", rpm:"lib64openshot-devel~0.2.5~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openshot19", rpm:"lib64openshot19~0.2.5~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64synfig-devel", rpm:"lib64synfig-devel~1.2.2~11.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64synfig0", rpm:"lib64synfig0~1.2.2~11.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wings-devel", rpm:"lib64wings-devel~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wings3", rpm:"lib64wings3~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wmaker-devel", rpm:"lib64wmaker-devel~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wmaker1", rpm:"lib64wmaker1~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wraster-devel", rpm:"lib64wraster-devel~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wraster6", rpm:"lib64wraster6~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wutil-devel", rpm:"lib64wutil-devel~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wutil5", rpm:"lib64wutil5~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine1.2-devel", rpm:"lib64xine1.2-devel~1.2.11~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine1.2-devel", rpm:"lib64xine1.2-devel~1.2.11~1.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine2", rpm:"lib64xine2~1.2.11~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xine2", rpm:"lib64xine2~1.2.11~1.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbar-devel", rpm:"lib64zbar-devel~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbar-gir1.0", rpm:"lib64zbar-gir1.0~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbar0", rpm:"lib64zbar0~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbargtk0", rpm:"lib64zbargtk0~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64zbarqt0", rpm:"lib64zbarqt0~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.2-devel", rpm:"libabydos0.2-devel~0.2.3~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.2-devel", rpm:"libabydos0.2-devel~0.2.3~4.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.2_0", rpm:"libabydos0.2_0~0.2.3~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabydos0.2_0", rpm:"libabydos0.2_0~0.2.3~4.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikam-devel", rpm:"libdigikam-devel~7.1.0~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamcore7.1.0", rpm:"libdigikamcore7.1.0~7.1.0~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamdatabase7.1.0", rpm:"libdigikamdatabase7.1.0~7.1.0~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamgui7.1.0", rpm:"libdigikamgui7.1.0~7.1.0~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.1.0.52~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.1.0.52~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_10", rpm:"libmagick-7Q16HDRI_10~7.1.0.52~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_10", rpm:"libmagick-7Q16HDRI_10~7.1.0.52~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.1.0.52~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.1.0.52~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot", rpm:"libopenshot~0.2.5~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot-devel", rpm:"libopenshot-devel~0.2.5~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot19", rpm:"libopenshot19~0.2.5~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynfig-devel", rpm:"libsynfig-devel~1.2.2~11.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynfig0", rpm:"libsynfig0~1.2.2~11.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwings-devel", rpm:"libwings-devel~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwings3", rpm:"libwings3~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmaker-devel", rpm:"libwmaker-devel~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmaker1", rpm:"libwmaker1~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwraster-devel", rpm:"libwraster-devel~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwraster6", rpm:"libwraster6~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwutil-devel", rpm:"libwutil-devel~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwutil5", rpm:"libwutil5~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine1.2-devel", rpm:"libxine1.2-devel~1.2.11~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine1.2-devel", rpm:"libxine1.2-devel~1.2.11~1.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine2", rpm:"libxine2~1.2.11~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxine2", rpm:"libxine2~1.2.11~1.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbar-devel", rpm:"libzbar-devel~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbar-gir1.0", rpm:"libzbar-gir1.0~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbar0", rpm:"libzbar0~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbargtk0", rpm:"libzbargtk0~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzbarqt0", rpm:"libzbarqt0~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mageia-windowmaker-desktop", rpm:"mageia-windowmaker-desktop~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.1.0.52~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.1.0.52~1.1.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-imagick", rpm:"php-imagick~3.4.5~0.git20201230.2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libopenshot", rpm:"python3-libopenshot~0.2.5~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-zbar", rpm:"python3-zbar~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"showfoto", rpm:"showfoto~7.1.0~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"synfig", rpm:"synfig~1.2.2~11.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"transcode", rpm:"transcode~1.1.7~29.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"windowmaker", rpm:"windowmaker~0.95.9~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine-lib1.2", rpm:"xine-lib1.2~1.2.11~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine-lib1.2", rpm:"xine-lib1.2~1.2.11~1.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine1.2-common", rpm:"xine1.2-common~1.2.11~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xine1.2-common", rpm:"xine1.2-common~1.2.11~1.2.mga8.tainted", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zbar", rpm:"zbar~0.23.1~5.2.mga8", rls:"MAGEIA8"))) {
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
