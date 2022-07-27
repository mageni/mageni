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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0131");
  script_cve_id("CVE-2021-43860", "CVE-2022-21682");
  script_tag(name:"creation_date", value:"2022-04-11 04:17:29 +0000 (Mon, 11 Apr 2022)");
  script_version("2022-04-11T04:17:29+0000");
  script_tag(name:"last_modification", value:"2022-04-12 10:03:57 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-21 19:43:00 +0000 (Fri, 21 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0131)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0131");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0131.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29885");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/security/advisories/GHSA-qpjc-vq3c-572j");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/security/advisories/GHSA-8ch7-5j3h-g4fx");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/APFTBYGJJVJPFVHRXUW5PII5XOAFI4KH/");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/releases/tag/1.10.7");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/releases/tag/1.12.4");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/G4SGDDYLN2BFKCHIDCXL2QTDVHPMZZM4/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IXKBERLJRYV7KXKGXOLI6IOXVBQNN4DP/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/UELF5NVMHRQ45DEBIRQGIVCV4PADFC37/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/F46WFOXXRE63UMMTLQB2FOJT4KLI5AR7/");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/releases/tag/1.12.5");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/releases/tag/1.12.6");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/T4OG73MX3JPZBHYMUXUULPTVL7ZOOTZ5/");
  script_xref(name:"URL", value:"https://github.com/flatpak/flatpak/releases/tag/1.12.7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'discover, flatpak, gnome-software, xdg-desktop-portal-kde' package(s) announced via the MGASA-2022-0131 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Flatpak doesn't properly validate that the permissions displayed to the
user for an app at install time match the actual permissions granted to
the app at runtime, in the case that there's a null byte in the metadata
file of an app. (CVE-2021-43860)
Path traversal vulnerability (CVE-2022-21682)
Various other fixes and enhancements included in update to version 1.12.7.");

  script_tag(name:"affected", value:"'discover, flatpak, gnome-software, xdg-desktop-portal-kde' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"discover", rpm:"discover~5.20.4~3.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.12.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-tests", rpm:"flatpak-tests~1.12.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-software", rpm:"gnome-software~3.38.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-software-devel", rpm:"gnome-software-devel~3.38.0~2.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak-devel", rpm:"lib64flatpak-devel~1.12.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak-gir1.0", rpm:"lib64flatpak-gir1.0~1.12.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak0", rpm:"lib64flatpak0~1.12.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak-devel", rpm:"libflatpak-devel~1.12.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak-gir1.0", rpm:"libflatpak-gir1.0~1.12.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0", rpm:"libflatpak0~1.12.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-kde", rpm:"xdg-desktop-portal-kde~5.20.4~2.1.mga8", rls:"MAGEIA8"))) {
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
