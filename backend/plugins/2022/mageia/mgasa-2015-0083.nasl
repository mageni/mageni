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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0083");
  script_cve_id("CVE-2014-9656", "CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9662", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9666", "CVE-2014-9667", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9672", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2015-0083)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0083");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0083.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15332");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1191095");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1191096");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-February/150162.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2, freetype2' package(s) announced via the MGASA-2015-0083 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated freetype2 packages fix security vulnerabilities:

The tt_sbit_decoder_load_image function in sfnt/ttsbit.c in FreeType before
2.5.4 does not properly check for an integer overflow, which allows remote
attackers to cause a denial of service (out-of-bounds read) or possibly have
unspecified other impact via a crafted OpenType font (CVE-2014-9656).

The tt_face_load_hdmx function in truetype/ttpload.c in FreeType before 2.5.4
does not establish a minimum record size, which allows remote attackers to cause
a denial of service (out-of-bounds read) or possibly have unspecified other
impact via a crafted TrueType font (CVE-2014-9657).

The tt_face_load_kern function in sfnt/ttkern.c in FreeType before 2.5.4
enforces an incorrect minimum table length, which allows remote attackers to
cause a denial of service (out-of-bounds read) or possibly have unspecified
other impact via a crafted TrueType font (CVE-2014-9658).

The _bdf_parse_glyphs function in bdf/bdflib.c in FreeType before 2.5.4 does not
properly handle a missing ENDCHAR record, which allows remote attackers to cause
a denial of service (NULL pointer dereference) or possibly have unspecified
other impact via a crafted BDF font (CVE-2014-9660).

type42/t42parse.c in FreeType before 2.5.4 does not consider that scanning can
be incomplete without triggering an error, which allows remote attackers to
cause a denial of service (use-after-free) or possibly have unspecified other
impact via a crafted Type42 font (CVE-2014-9661).

cff/cf2ft.c in FreeType before 2.5.4 does not validate the return values of
point-allocation functions, which allows remote attackers to cause a denial of
service (heap-based buffer overflow) or possibly have unspecified other impact
via a crafted OTF font (CVE-2014-9662).

The tt_cmap4_validate function in sfnt/ttcmap.c in FreeType before 2.5.4
validates a certain length field before that field's value is completely
calculated, which allows remote attackers to cause a denial of service
(out-of-bounds read) or possibly have unspecified other impact via a crafted
cmap SFNT table (CVE-2014-9663).

FreeType before 2.5.4 does not check for the end of the data during certain
parsing actions, which allows remote attackers to cause a denial of service
(out-of-bounds read) or possibly have unspecified other impact via a crafted
Type42 font, related to type42/t42parse.c and type1/t1load.c (CVE-2014-9664).

The tt_sbit_decoder_init function in sfnt/ttsbit.c in FreeType before 2.5.4
proceeds with a count-to-size association without restricting the count value,
which allows remote attackers to cause a denial of service (integer overflow and
out-of-bounds read) or possibly have unspecified other impact via a crafted
embedded bitmap (CVE-2014-9666).

sfnt/ttload.c in FreeType before 2.5.4 proceeds with offset+length calculations
without restricting the values, which allows remote attackers to cause a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'freetype2, freetype2' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.5.0.1~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2", rpm:"freetype2~2.5.0.1~3.3.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-demos", rpm:"freetype2-demos~2.5.0.1~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-demos", rpm:"freetype2-demos~2.5.0.1~3.3.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6", rpm:"lib64freetype6~2.5.0.1~3.3.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6", rpm:"lib64freetype6~2.5.0.1~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-devel", rpm:"lib64freetype6-devel~2.5.0.1~3.3.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-devel", rpm:"lib64freetype6-devel~2.5.0.1~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-static-devel", rpm:"lib64freetype6-static-devel~2.5.0.1~3.3.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freetype6-static-devel", rpm:"lib64freetype6-static-devel~2.5.0.1~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.5.0.1~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.5.0.1~3.3.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-devel", rpm:"libfreetype6-devel~2.5.0.1~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-devel", rpm:"libfreetype6-devel~2.5.0.1~3.3.mga4.tainted", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-static-devel", rpm:"libfreetype6-static-devel~2.5.0.1~3.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-static-devel", rpm:"libfreetype6-static-devel~2.5.0.1~3.3.mga4.tainted", rls:"MAGEIA4"))) {
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
