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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0777.1");
  script_cve_id("CVE-2021-25316");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:41 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-09T14:56:41+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-21 17:30:00 +0000 (Wed, 21 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0777-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0777-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210777-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 's390-tools' package(s) announced via the SUSE-SU-2021:0777-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for s390-tools fixes the following issues:

Fixed an issue where IPL was not working when bootloader was installed
 on a SCSI disk with 4k physical blocksize without using a devicemapper
 target (bsc#1183041).

CVE-2021-25316: Do not use predictable temporary file names
 (bsc#1182777).

Made the name of the temporary configuration file in /tmp/ unpredictable
 (bsc#1182876).

Changing the scheduler from 'deadline' to the newly created
 'mq-deadline' scheduler (bsc#1176574)");

  script_tag(name:"affected", value:"'s390-tools' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2");

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

if(release == "SLES15.0SP2") {
  if(!isnull(res = isrpmvuln(pkg:"osasnmpd", rpm:"osasnmpd~2.11.0~9.20.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"osasnmpd-debuginfo", rpm:"osasnmpd-debuginfo~2.11.0~9.20.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools", rpm:"s390-tools~2.11.0~9.20.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-debuginfo", rpm:"s390-tools-debuginfo~2.11.0~9.20.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-debugsource", rpm:"s390-tools-debugsource~2.11.0~9.20.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-hmcdrvfs", rpm:"s390-tools-hmcdrvfs~2.11.0~9.20.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-hmcdrvfs-debuginfo", rpm:"s390-tools-hmcdrvfs-debuginfo~2.11.0~9.20.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-zdsfs", rpm:"s390-tools-zdsfs~2.11.0~9.20.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-zdsfs-debuginfo", rpm:"s390-tools-zdsfs-debuginfo~2.11.0~9.20.1", rls:"SLES15.0SP2"))){
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
