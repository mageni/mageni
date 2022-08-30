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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0296");
  script_cve_id("CVE-2022-30550");
  script_tag(name:"creation_date", value:"2022-08-26 04:58:48 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T04:58:48+0000");
  script_tag(name:"last_modification", value:"2022-08-26 04:58:48 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-25 23:48:00 +0000 (Mon, 25 Jul 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0296)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0296");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0296.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30618");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2022-July/000477.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5509-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/532QM5GABOZURM72SXKWEPBBQKUHLQC3/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OQ5EW32AQSRSHPFQZM5W3PEYEKPBKGNA/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot' package(s) announced via the MGASA-2022-0296 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the auth component in Dovecot 2.2 and 2.3
before 2.3.20. When two passdb configuration entries exist with the same
driver and args settings, incorrect username_filter and mechanism settings
can be applied to passdb definitions. These incorrectly applied settings
can lead to an unintended security configuration and can permit privilege
escalation in certain configurations. The documentation does not advise
against the use of passdb definitions that have the same driver and args
settings. One such configuration would be where an administrator wishes to
use the same PAM configuration or passwd file for both normal and master
users but use the username_filter setting to restrict which of the users
is able to be a master user. (CVE-2022-30550)");

  script_tag(name:"affected", value:"'dovecot' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.3.17.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~2.3.17.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole", rpm:"dovecot-pigeonhole~2.3.17.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole-devel", rpm:"dovecot-pigeonhole-devel~2.3.17.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-gssapi", rpm:"dovecot-plugins-gssapi~2.3.17.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-ldap", rpm:"dovecot-plugins-ldap~2.3.17.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-mysql", rpm:"dovecot-plugins-mysql~2.3.17.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-pgsql", rpm:"dovecot-plugins-pgsql~2.3.17.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-sqlite", rpm:"dovecot-plugins-sqlite~2.3.17.1~1.2.mga8", rls:"MAGEIA8"))) {
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
