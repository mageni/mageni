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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0188");
  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717", "CVE-2016-3718");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 13:29:00 +0000 (Mon, 15 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2016-0188)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0188");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0188.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18347");
  script_xref(name:"URL", value:"http://git.imagemagick.org/repos/ImageMagick/blob/dce8f08c7bf7a92c451f45a684ca96434684a69e/ChangeLog");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2016-0726.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick, ruby-rmagick' package(s) announced via the MGASA-2016-0188 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ImageMagick did not properly sanitize certain input
before passing it to the delegate functionality. A remote attacker could
create a specially crafted image that, when processed by an application
using ImageMagick or an unsuspecting user using the ImageMagick utilities,
would lead to arbitrary execution of shell commands with the privileges of
the user running the application (CVE-2016-3714).

It was discovered that certain ImageMagick coders and pseudo-protocols did
not properly prevent security sensitive operations when processing
specially crafted images. A remote attacker could create a specially
crafted image that, when processed by an application using ImageMagick or
an unsuspecting user using the ImageMagick utilities, would allow the
attacker to delete, move, or disclose the contents of arbitrary files
(CVE-2016-3715, CVE-2016-3716, CVE-2016-3717).

A server-side request forgery flaw was discovered in the way ImageMagick
processed certain images. A remote attacker could exploit this flaw to
mislead an application using ImageMagick or an unsuspecting user using the
ImageMagick utilities into, for example, performing HTTP(S) requests or
opening FTP sessions via specially crafted images (CVE-2016-3718).

The imagemagick package has been updated to version 6.9.4-2 to fix these
issues and several other bugs.");

  script_tag(name:"affected", value:"'imagemagick, ruby-rmagick' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.9.4.2~0.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.9.4.2~0.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.9.4.2~0.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-6Q16_6", rpm:"lib64magick++-6Q16_6~6.9.4.2~0.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-6Q16_2", rpm:"lib64magick-6Q16_2~6.9.4.2~0.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.9.4.2~0.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-6Q16_6", rpm:"libmagick++-6Q16_6~6.9.4.2~0.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-6Q16_2", rpm:"libmagick-6Q16_2~6.9.4.2~0.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.9.4.2~0.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.9.4.2~0.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rmagick", rpm:"ruby-rmagick~2.13.2~21.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rmagick-doc", rpm:"ruby-rmagick-doc~2.13.2~21.1.mga5", rls:"MAGEIA5"))) {
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
