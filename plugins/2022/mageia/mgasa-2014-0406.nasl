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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0406");
  script_cve_id("CVE-2014-4330");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:49:00 +0000 (Tue, 09 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2014-0406)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0406");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0406.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14170");
  script_xref(name:"URL", value:"https://www.lsexperts.de/advisories/lse-2014-06-10.txt");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-September/139441.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14098");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the MGASA-2014-0406 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated perl package fixes security vulnerability:

The Dumper method in Data::Dumper before 2.154, as used in Perl 5.20.1 and
earlier, allows context-dependent attackers to cause a denial of service
(stack consumption and crash) via an Array-Reference with many nested
Array-References, which triggers a large number of recursive calls to the
DD_dump function (CVE-2014-4330).

Also, the Text::Wrap version provided in perl contains a bug that can lead
to a code path that shouldn't be hit. This can lead to crashes in other
software, such as Bugzilla.

The Text::Wrap module bundled with Perl has been patched and the
Data::Dumper module bundled with Perl has been updated to fix these issues.");

  script_tag(name:"affected", value:"'perl' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.18.1~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.18.1~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.18.1~3.2.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.18.1~3.2.mga4", rls:"MAGEIA4"))) {
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
