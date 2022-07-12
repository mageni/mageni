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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0057");
  script_cve_id("CVE-2017-5884", "CVE-2017-5885");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0057)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0057");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0057.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20244");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/02/05/5");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=778048");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=778050");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk-vnc' package(s) announced via the MGASA-2017-0057 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that gtk-vnc code does not properly check boundaries of
subrectangle-containing tiles. A malicious server can use this to
overwrite parts of the client memory (CVE-2017-5884).

In addition, the vnc_connection_server_message() and vnc_color_map_set()
functions do not check for integer overflow properly, leading to a
malicious server being able to overwrite parts of the client memory
(CVE-2017-5885).");

  script_tag(name:"affected", value:"'gtk-vnc' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gtk-vnc", rpm:"gtk-vnc~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk-vnc-i18n", rpm:"gtk-vnc-i18n~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk-vnc1.0-devel", rpm:"lib64gtk-vnc1.0-devel~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk-vnc1.0_0", rpm:"lib64gtk-vnc1.0_0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk-vnc2.0-devel", rpm:"lib64gtk-vnc2.0-devel~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk-vnc2.0_0", rpm:"lib64gtk-vnc2.0_0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtkvnc-gir1.0", rpm:"lib64gtkvnc-gir1.0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtkvnc-gir2.0", rpm:"lib64gtkvnc-gir2.0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gvnc-gir1.0", rpm:"lib64gvnc-gir1.0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gvnc1.0-devel", rpm:"lib64gvnc1.0-devel~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gvnc1.0_0", rpm:"lib64gvnc1.0_0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc1.0-devel", rpm:"libgtk-vnc1.0-devel~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc1.0_0", rpm:"libgtk-vnc1.0_0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc2.0-devel", rpm:"libgtk-vnc2.0-devel~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc2.0_0", rpm:"libgtk-vnc2.0_0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtkvnc-gir1.0", rpm:"libgtkvnc-gir1.0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtkvnc-gir2.0", rpm:"libgtkvnc-gir2.0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc-gir1.0", rpm:"libgvnc-gir1.0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc1.0-devel", rpm:"libgvnc1.0-devel~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc1.0_0", rpm:"libgvnc1.0_0~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gtk-vnc", rpm:"python-gtk-vnc~0.5.3~6.1.mga5", rls:"MAGEIA5"))) {
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
