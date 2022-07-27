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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0229");
  script_cve_id("CVE-2016-10046", "CVE-2016-10051", "CVE-2016-10052", "CVE-2016-10053", "CVE-2016-10054", "CVE-2016-10055", "CVE-2016-10056", "CVE-2016-10057", "CVE-2016-10058", "CVE-2016-10068", "CVE-2016-10144", "CVE-2016-10145", "CVE-2016-10146", "CVE-2016-5010", "CVE-2016-6491", "CVE-2016-6823", "CVE-2016-7101", "CVE-2016-7799", "CVE-2016-7906", "CVE-2016-8677", "CVE-2016-8678", "CVE-2016-8707", "CVE-2016-8862", "CVE-2016-8866", "CVE-2016-9298", "CVE-2016-9556", "CVE-2016-9559", "CVE-2016-9773", "CVE-2017-11352", "CVE-2017-11403", "CVE-2017-11446", "CVE-2017-11523", "CVE-2017-11533", "CVE-2017-11535", "CVE-2017-11537", "CVE-2017-11639", "CVE-2017-11640", "CVE-2017-12428", "CVE-2017-12431", "CVE-2017-12432", "CVE-2017-12434", "CVE-2017-12587", "CVE-2017-12640", "CVE-2017-12671", "CVE-2017-12877", "CVE-2017-12983", "CVE-2017-13134", "CVE-2017-13139", "CVE-2017-13140", "CVE-2017-13141", "CVE-2017-13142", "CVE-2017-13143", "CVE-2017-13144", "CVE-2017-13145", "CVE-2017-13758", "CVE-2017-13768", "CVE-2017-13769", "CVE-2017-14224", "CVE-2017-14607", "CVE-2017-14682", "CVE-2017-14741", "CVE-2017-14989", "CVE-2017-15277", "CVE-2017-16546", "CVE-2017-17499", "CVE-2017-17504", "CVE-2017-17879", "CVE-2017-5506", "CVE-2017-5507", "CVE-2017-5508", "CVE-2017-5509", "CVE-2017-5510", "CVE-2017-5511", "CVE-2017-7606", "CVE-2017-7619", "CVE-2017-7941", "CVE-2017-7942", "CVE-2017-7943", "CVE-2017-8343", "CVE-2017-8344", "CVE-2017-8345", "CVE-2017-8346", "CVE-2017-8347", "CVE-2017-8348", "CVE-2017-8349", "CVE-2017-8350", "CVE-2017-8351", "CVE-2017-8352", "CVE-2017-8353", "CVE-2017-8354", "CVE-2017-8355", "CVE-2017-8356", "CVE-2017-8357", "CVE-2017-8765", "CVE-2017-8830", "CVE-2017-9098", "CVE-2017-9141", "CVE-2017-9142", "CVE-2017-9143", "CVE-2017-9144", "CVE-2017-9439", "CVE-2017-9440", "CVE-2017-9500", "CVE-2017-9501");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0229)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0229");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0229.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19078");
  script_xref(name:"URL", value:"http://git.imagemagick.org/repos/ImageMagick/blob/ImageMagick-6/ChangeLog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'converseen, cuneiform-linux, dvdauthor, emacs, imagemagick, inkscape, k3d, kxstitch, libopenshot, ocaml-glmlite, perl-Image-SubImageFind, pfstools, php-imagick, php-magickwand, psiconv, pythonmagick, ruby-rmagick, synfig, vdr-plugin-skinelchi, vdr-plugin-skinenigmang' package(s) announced via the MGASA-2018-0229 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The imagemagick package has been updated to version 6.9.9.41 which
fixes several unspecified security vulnerabilities.
This update fixes several vulnerabilities in imagemagick, including:
Various memory handling problems and cases of missing or incomplete
input sanitising may result in denial of service, memory disclosure
or the execution of arbitrary code if malformed GIF, TTF, SVG, TIFF,
PCX, JPG or SFW files are processed.

Several packages have been rebuilt for the updated ImageMagick.");

  script_tag(name:"affected", value:"'converseen, cuneiform-linux, dvdauthor, emacs, imagemagick, inkscape, k3d, kxstitch, libopenshot, ocaml-glmlite, perl-Image-SubImageFind, pfstools, php-imagick, php-magickwand, psiconv, pythonmagick, ruby-rmagick, synfig, vdr-plugin-skinelchi, vdr-plugin-skinenigmang' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"converseen", rpm:"converseen~0.9.6.2~1.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cuneiform-linux", rpm:"cuneiform-linux~1.1.0~9.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvdauthor", rpm:"dvdauthor~0.7.2~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs", rpm:"emacs~24.5~8.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-common", rpm:"emacs-common~24.5~8.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-doc", rpm:"emacs-doc~24.5~8.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-el", rpm:"emacs-el~24.5~8.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-leim", rpm:"emacs-leim~24.5~8.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-nox", rpm:"emacs-nox~24.5~8.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.9.9.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.9.9.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.9.9.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"inkscape", rpm:"inkscape~0.92.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"k3d", rpm:"k3d~0.8.0.5~5.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"k3d-devel", rpm:"k3d-devel~0.8.0.5~5.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kxstitch", rpm:"kxstitch~2.0.0~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kxstitch-handbook", rpm:"kxstitch-handbook~2.0.0~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cuneiform-devel", rpm:"lib64cuneiform-devel~1.1.0~9.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cuneiform0", rpm:"lib64cuneiform0~1.1.0~9.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-6Q16_8", rpm:"lib64magick++-6Q16_8~6.9.9.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-6Q16_6", rpm:"lib64magick-6Q16_6~6.9.9.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.9.9.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openshot-devel", rpm:"lib64openshot-devel~0.1.8~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openshot13", rpm:"lib64openshot13~0.1.8~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pfstools-devel", rpm:"lib64pfstools-devel~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pfstools2", rpm:"lib64pfstools2~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64psiconv-devel", rpm:"lib64psiconv-devel~0.9.8~26.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64psiconv6", rpm:"lib64psiconv6~0.9.8~26.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64synfig-devel", rpm:"lib64synfig-devel~1.2.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64synfig0", rpm:"lib64synfig0~1.2.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcuneiform-devel", rpm:"libcuneiform-devel~1.1.0~9.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcuneiform0", rpm:"libcuneiform0~1.1.0~9.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-6Q16_8", rpm:"libmagick++-6Q16_8~6.9.9.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-6Q16_6", rpm:"libmagick-6Q16_6~6.9.9.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.9.9.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot", rpm:"libopenshot~0.1.8~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot-devel", rpm:"libopenshot-devel~0.1.8~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenshot13", rpm:"libopenshot13~0.1.8~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpfstools-devel", rpm:"libpfstools-devel~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpfstools2", rpm:"libpfstools2~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpsiconv-devel", rpm:"libpsiconv-devel~0.9.8~26.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpsiconv6", rpm:"libpsiconv6~0.9.8~26.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynfig-devel", rpm:"libsynfig-devel~1.2.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsynfig0", rpm:"libsynfig0~1.2.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-glmlite", rpm:"ocaml-glmlite~0.03.51~17.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-glmlite-devel", rpm:"ocaml-glmlite-devel~0.03.51~17.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.9.9.41~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-SubImageFind", rpm:"perl-Image-SubImageFind~0.30.0~6.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfscalibration", rpm:"pfscalibration~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstmo", rpm:"pfstmo~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools", rpm:"pfstools~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-exr", rpm:"pfstools-exr~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-glview", rpm:"pfstools-glview~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-imgmagick", rpm:"pfstools-imgmagick~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-octave", rpm:"pfstools-octave~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pfstools-qt", rpm:"pfstools-qt~2.0.6~3.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-imagick", rpm:"php-imagick~3.4.1~6.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-magickwand", rpm:"php-magickwand~1.0.9.2~10.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"psiconv", rpm:"psiconv~0.9.8~26.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libopenshot", rpm:"python3-libopenshot~0.1.8~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pythonmagick", rpm:"pythonmagick~0.9.12~7.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rmagick", rpm:"ruby-rmagick~2.15.4~12.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rmagick-doc", rpm:"ruby-rmagick-doc~2.15.4~12.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"synfig", rpm:"synfig~1.2.1~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vdr-plugin-skinelchi", rpm:"vdr-plugin-skinelchi~0.2.8~8.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vdr-plugin-skinenigmang", rpm:"vdr-plugin-skinenigmang~0.1.2~10.2.mga6", rls:"MAGEIA6"))) {
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
