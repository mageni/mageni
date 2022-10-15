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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3524.1");
  script_cve_id("CVE-2022-32213", "CVE-2022-32215", "CVE-2022-35255", "CVE-2022-35256");
  script_tag(name:"creation_date", value:"2022-10-06 04:32:08 +0000 (Thu, 06 Oct 2022)");
  script_version("2022-10-06T10:41:20+0000");
  script_tag(name:"last_modification", value:"2022-10-06 10:41:20 +0000 (Thu, 06 Oct 2022)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-21 15:18:00 +0000 (Thu, 21 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3524-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3524-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223524-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs16' package(s) announced via the SUSE-SU-2022:3524-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs16 fixes the following issues:

Updated to version 16.17.1:

CVE-2022-32213: Fixed bypass via obs-fold mechanic (bsc#1201325).

CVE-2022-32215: Fixed incorrect Parsing of Multi-line Transfer-Encoding
 (bsc#1201327).

CVE-2022-35256: Fixed incorrect Parsing of Header Fields (bsc#1203832).

CVE-2022-35255: FIxed weak randomness in WebCrypto keygen (bsc#1203831).");

  script_tag(name:"affected", value:"'nodejs16' package(s) on SUSE Linux Enterprise Module for Web Scripting 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs16", rpm:"nodejs16~16.17.1~8.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-debuginfo", rpm:"nodejs16-debuginfo~16.17.1~8.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-debugsource", rpm:"nodejs16-debugsource~16.17.1~8.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-devel", rpm:"nodejs16-devel~16.17.1~8.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-docs", rpm:"nodejs16-docs~16.17.1~8.12.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm16", rpm:"npm16~16.17.1~8.12.1", rls:"SLES12.0"))) {
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
