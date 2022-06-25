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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0169");
  script_cve_id("CVE-2013-2007");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-29 01:33:00 +0000 (Tue, 29 Aug 2017)");

  script_name("Mageia: Security Advisory (MGASA-2013-0169)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0169");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0169.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10431");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2013-0896.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu, qemu' package(s) announced via the MGASA-2013-0169 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that QEMU Guest Agent (the 'qemu-ga' service) created
certain files with world-writable permissions when run in daemon mode
(the default mode). An unprivileged guest user could use this flaw to
consume all free space on the partition containing the qemu-ga log file, or
modify the contents of the log. When a UNIX domain socket transport was
explicitly configured to be used (not the default), an unprivileged guest
user could potentially use this flaw to escalate their privileges in the
guest (CVE-2013-2007).

Note: This update requires manual action. Refer below for details.

This update does not change the permissions of the existing log file or
the UNIX domain socket. For these to be changed, stop the qemu-ga service,
and then manually remove all 'group' and 'other' permissions on the
affected files, or remove the files.

Also note that after installing this update, files created by the
guest-file-open QEMU Monitor Protocol (QMP) command will still continue to
be created with world-writable permissions for backwards compatibility.");

  script_tag(name:"affected", value:"'qemu, qemu' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~1.0~6.5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.0~6.5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~1.2.0~8.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.2.0~8.1.mga3", rls:"MAGEIA3"))) {
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
