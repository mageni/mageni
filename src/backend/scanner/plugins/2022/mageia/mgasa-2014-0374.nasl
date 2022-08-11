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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0374");
  script_cve_id("CVE-2014-1949");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-10-13 16:38:00 +0000 (Tue, 13 Oct 2015)");

  script_name("Mageia: Security Advisory (MGASA-2014-0374)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0374");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0374.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14013");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=386569");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=709491");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=719314");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=719977");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=722106");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-August/137123.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk+3.0' package(s) announced via the MGASA-2014-0374 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated gtk+3.0 packages fix security vulnerability:

Clemens Fries reported that, when using Cinnamon, it was possible to bypass
the screensaver lock. An attacker with physical access to the machine could
use this flaw to take over the locked desktop session (CVE-2014-1949).

This was fixed by including a patch for the root cause of the issue in
gtk+3.0, which came from the implementation of popup menus in GtkWindow
(bgo#722106).

This update also includes other patches from upstream to fix bugs affecting
GtkFileChooser (bgo#386569, bgo#719977) and GtkSpinButton (bgo#709491), and a
crash related to clipboard handling (bgo#719314).");

  script_tag(name:"affected", value:"'gtk+3.0' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"gtk+3.0", rpm:"gtk+3.0~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gail3.0-devel", rpm:"lib64gail3.0-devel~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gail3_0", rpm:"lib64gail3_0~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+3.0-devel", rpm:"lib64gtk+3.0-devel~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+3_0", rpm:"lib64gtk+3_0~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk-gir3.0", rpm:"lib64gtk-gir3.0~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgail3.0-devel", rpm:"libgail3.0-devel~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgail3_0", rpm:"libgail3_0~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+3.0-devel", rpm:"libgtk+3.0-devel~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+3_0", rpm:"libgtk+3_0~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-gir3.0", rpm:"libgtk-gir3.0~3.10.6~4.1.mga4", rls:"MAGEIA4"))) {
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
