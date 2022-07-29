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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2543.1");
  script_tag(name:"creation_date", value:"2022-07-26 04:48:09 +0000 (Tue, 26 Jul 2022)");
  script_version("2022-07-26T10:10:41+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:41 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2543-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2543-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222543-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 's390-tools' package(s) announced via the SUSE-SU-2022:2543-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of s390-tools fixes the following issues:

Fixed KMIP plugin failing to connection to KMIP server.

 When a zkey key repository is bound to the KMIP plugin, and the connection to the KMIP server is to be configired using command 'zkey kms configure --kmip-server ', it fails to connect to the specified KMIP server. (bsc#1199649)

rebuild with new secure boot key due to grub2 boothole 3 issues
 (bsc#1198581)");

  script_tag(name:"affected", value:"'s390-tools' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libekmfweb1", rpm:"libekmfweb1~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libekmfweb1-debuginfo", rpm:"libekmfweb1-debuginfo~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libekmfweb1-devel", rpm:"libekmfweb1-devel~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmipclient1", rpm:"libkmipclient1~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkmipclient1-debuginfo", rpm:"libkmipclient1-debuginfo~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"osasnmpd", rpm:"osasnmpd~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"osasnmpd-debuginfo", rpm:"osasnmpd-debuginfo~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools", rpm:"s390-tools~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-chreipl-fcp-mpath", rpm:"s390-tools-chreipl-fcp-mpath~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-debuginfo", rpm:"s390-tools-debuginfo~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-debugsource", rpm:"s390-tools-debugsource~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-hmcdrvfs", rpm:"s390-tools-hmcdrvfs~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-hmcdrvfs-debuginfo", rpm:"s390-tools-hmcdrvfs-debuginfo~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-zdsfs", rpm:"s390-tools-zdsfs~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390-tools-zdsfs-debuginfo", rpm:"s390-tools-zdsfs-debuginfo~2.19.0~150400.7.4.1", rls:"SLES15.0SP4"))) {
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
