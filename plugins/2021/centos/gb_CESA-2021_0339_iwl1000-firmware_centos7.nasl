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
  script_oid("1.3.6.1.4.1.25623.1.0.883323");
  script_version("2021-02-05T06:37:30+0000");
  script_cve_id("CVE-2020-12321");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-02-05 17:59:24 +0000 (Fri, 05 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-04 04:00:51 +0000 (Thu, 04 Feb 2021)");
  script_name("CentOS: Security Advisory for iwl1000-firmware (CESA-2021:0339)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:0339");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-February/048265.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iwl1000-firmware'
  package(s) announced via the CESA-2021:0339 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The linux-firmware packages contain all of the firmware files that are
required by various devices to operate.

Security Fix(es):

  * hardware: buffer overflow in bluetooth firmware (CVE-2020-12321)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'iwl1000-firmware' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"iwl1000-firmware", rpm:"iwl1000-firmware~39.31.5.1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl100-firmware", rpm:"iwl100-firmware~39.31.5.1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl105-firmware", rpm:"iwl105-firmware~18.168.6.1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl135-firmware", rpm:"iwl135-firmware~18.168.6.1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl2000-firmware", rpm:"iwl2000-firmware~18.168.6.1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl2030-firmware", rpm:"iwl2030-firmware~18.168.6.1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl3160-firmware", rpm:"iwl3160-firmware~25.30.13.0~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl3945-firmware", rpm:"iwl3945-firmware~15.32.2.9~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl4965-firmware", rpm:"iwl4965-firmware~228.61.2.24~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl5000-firmware", rpm:"iwl5000-firmware~8.83.5.1_1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl5150-firmware", rpm:"iwl5150-firmware~8.24.2.2~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl6000-firmware", rpm:"iwl6000-firmware~9.221.4.1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl6000g2a-firmware", rpm:"iwl6000g2a-firmware~18.168.6.1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl6000g2b-firmware", rpm:"iwl6000g2b-firmware~18.168.6.1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl6050-firmware", rpm:"iwl6050-firmware~41.28.5.1~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwl7260-firmware", rpm:"iwl7260-firmware~25.30.13.0~80.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20200421~80.git78c0348.el7_9", rls:"CentOS7"))) {
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