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
  script_oid("1.3.6.1.4.1.25623.1.0.884243");
  script_version("2022-09-16T07:39:11+0000");
  script_cve_id("CVE-2022-31676");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-16 07:39:11 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-14 01:00:48 +0000 (Wed, 14 Sep 2022)");
  script_name("CentOS: Security Advisory for open-vm-tools (CESA-2022:6381)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2022:6381");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2022-September/073638.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-vm-tools'
  package(s) announced via the CESA-2022:6381 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Open Virtual Machine Tools are the open source implementation of the
VMware Tools. They are a set of guest operating system virtualization
components that enhance performance and user experience of virtual
machines.

Security Fix(es):

  * open-vm-tools: local root privilege escalation in the virtual machine
(CVE-2022-31676)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'open-vm-tools' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~11.0.5~3.el7_9.4", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~11.0.5~3.el7_9.4", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-devel", rpm:"open-vm-tools-devel~11.0.5~3.el7_9.4", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-test", rpm:"open-vm-tools-test~11.0.5~3.el7_9.4", rls:"CentOS7"))) {
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