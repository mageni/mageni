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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0058");
  script_cve_id("CVE-2012-0786", "CVE-2012-0787", "CVE-2013-6412");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-01-23 17:55:00 +0000 (Thu, 23 Jan 2014)");

  script_name("Mageia: Security Advisory (MGASA-2014-0058)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0058");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0058.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11721");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-1537.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-0044.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'augeas' package(s) announced via the MGASA-2014-0058 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were found in the way Augeas handled configuration files
when updating them. An application using Augeas to update configuration
files in a directory that is writable to by a different user (for example,
an application running as root that is updating files in a directory owned
by a non-root service user) could have been tricked into overwriting
arbitrary files or leaking information via a symbolic link or mount point
attack (CVE-2012-0786, CVE-2012-0787).

A flaw was found in the way Augeas handled certain umask settings when
creating new configuration files. This flaw could result in configuration
files being created as world writable, allowing unprivileged local users to
modify their content (CVE-2013-6412).");

  script_tag(name:"affected", value:"'augeas' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"augeas", rpm:"augeas~1.1.0~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"augeas-lenses", rpm:"augeas-lenses~1.1.0~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64augeas-devel", rpm:"lib64augeas-devel~1.1.0~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64augeas0", rpm:"lib64augeas0~1.1.0~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fa1", rpm:"lib64fa1~1.1.0~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaugeas-devel", rpm:"libaugeas-devel~1.1.0~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaugeas0", rpm:"libaugeas0~1.1.0~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfa1", rpm:"libfa1~1.1.0~1.1.mga3", rls:"MAGEIA3"))) {
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
