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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0044");
  script_cve_id("CVE-2013-7252");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-02 13:58:00 +0000 (Tue, 02 Aug 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0044)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0044");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0044.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14997");
  script_xref(name:"URL", value:"https://www.kde.org/info/security/advisory-20150109-1.txt");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-January/148090.html");
  script_xref(name:"URL", value:"https://bugs.kde.org/show_bug.cgi?id=342391");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14851");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=4461");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdebase4-runtime' package(s) announced via the MGASA-2015-0044 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated kdebase4-runtime packages fix security vulnerability:

kwalletd in KWallet before KDE Applications 14.12.0 uses Blowfish with ECB
mode instead of CBC mode when encrypting the password store, which makes it
easier for attackers to guess passwords via a codebook attack (CVE-2013-7252).

This update also fixes some additional issues:
- encoding in KDEsuDialog (mga#14851)
- kio_sftp can corrupts files when reading (bko#342391)
- use euro currency for Lithuania
- save the default file manager, email client and browser in mimeapps.list
 [Default Applications] for a better interoperability with most of GTK
 applications (mga#4461)");

  script_tag(name:"affected", value:"'kdebase4-runtime' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-runtime", rpm:"kdebase4-runtime~4.12.5~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-runtime-devel", rpm:"kdebase4-runtime-devel~4.12.5~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdebase4-runtime-handbook", rpm:"kdebase4-runtime-handbook~4.12.5~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kwallet-daemon", rpm:"kwallet-daemon~4.12.5~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64kwalletbackend4", rpm:"lib64kwalletbackend4~4.12.5~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64molletnetwork4", rpm:"lib64molletnetwork4~4.12.5~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkwalletbackend4", rpm:"libkwalletbackend4~4.12.5~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmolletnetwork4", rpm:"libmolletnetwork4~4.12.5~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nepomuk", rpm:"nepomuk~4.12.5~1.3.mga4", rls:"MAGEIA4"))) {
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
