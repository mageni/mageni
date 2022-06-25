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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1516.1");
  script_cve_id("CVE-2016-9011", "CVE-2019-6978");
  script_tag(name:"creation_date", value:"2022-05-05 04:28:31 +0000 (Thu, 05 May 2022)");
  script_version("2022-05-05T04:28:31+0000");
  script_tag(name:"last_modification", value:"2022-05-05 10:20:08 +0000 (Thu, 05 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-05 00:29:00 +0000 (Fri, 05 Apr 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1516-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1516-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221516-1/");
  script_xref(name:"URL", value:"https://github.com/caolanm/libwmf");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwmf' package(s) announced via the SUSE-SU-2022:1516-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libwmf fixes the following issues:

libwmf was updated to 0.2.12:

upstream changed to fork from Fedora: [link moved to references]

merged all the pending fixes

merge in fixes for libgd CVE-2019-6978 (bsc#1123522)

fixed memory allocation failure (CVE-2016-9011)

Fixes for %_libexecdir changing to /usr/libexec (bsc#1174075)");

  script_tag(name:"affected", value:"'libwmf' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libwmf-0_2-7", rpm:"libwmf-0_2-7~0.2.12~150000.4.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf-0_2-7-debuginfo", rpm:"libwmf-0_2-7-debuginfo~0.2.12~150000.4.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf-debugsource", rpm:"libwmf-debugsource~0.2.12~150000.4.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf-devel", rpm:"libwmf-devel~0.2.12~150000.4.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf-gnome", rpm:"libwmf-gnome~0.2.12~150000.4.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf-gnome-debuginfo", rpm:"libwmf-gnome-debuginfo~0.2.12~150000.4.4.1", rls:"SLES15.0SP4"))) {
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
