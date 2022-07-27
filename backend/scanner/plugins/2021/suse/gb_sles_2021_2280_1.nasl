# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2280.1");
  script_cve_id("CVE-2019-3688", "CVE-2019-3690", "CVE-2020-8013");
  script_tag(name:"creation_date", value:"2021-07-10 02:29:40 +0000 (Sat, 10 Jul 2021)");
  script_version("2021-07-12T12:44:11+0000");
  script_tag(name:"last_modification", value:"2021-07-13 11:35:30 +0000 (Tue, 13 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-20 16:15:00 +0000 (Fri, 20 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2280-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2280-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212280-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'permissions' package(s) announced via the SUSE-SU-2021:2280-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for permissions fixes the following issues:

Fork package for 12-SP5 (bsc#1155939)

make btmp root:utmp (bsc#1050467, bsc#1182899)

pcp: remove no longer needed / conflicting entries (bsc#1171883). Fixes
 a potential security issue.

do not follow symlinks that are the final path element (CVE-2020-8013,
 bsc#1163922)

fix handling of relative directory symlinks in chkstat

whitelist postgres sticky directories (bsc#1123886)

fix regression where chkstat breaks without /proc available
 (bsc#1160764, bsc#1160594)

fix capability handling when doing multiple permission changes at once
 (bsc#1161779,

fix invalid free() when permfiles points to argv (bsc#1157198)

the error should be reported for permfiles[i], not argv[i], as these are
 not the same files. (bsc#1047247, bsc#1097665)

fix /usr/sbin/pinger ownership to root:squid (bsc#1093414, CVE-2019-3688)

fix privilege escalation through untrusted symlinks (bsc#1150734,
 CVE-2019-3690)");

  script_tag(name:"affected", value:"'permissions' package(s) on SUSE Linux Enterprise Server 12-SP5");

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

if(release == "SLES12.0SP5") {
  if(!isnull(res = isrpmvuln(pkg:"permissions", rpm:"permissions~20170707~6.4.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"permissions-debuginfo", rpm:"permissions-debuginfo~20170707~6.4.1", rls:"SLES12.0SP5"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"permissions-debugsource", rpm:"permissions-debugsource~20170707~6.4.1", rls:"SLES12.0SP5"))){
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
