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
  script_oid("1.3.6.1.4.1.25623.1.0.884240");
  script_version("2022-09-02T12:48:40+0000");
  script_cve_id("CVE-2022-2526");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-02 12:48:40 +0000 (Fri, 02 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-02 01:00:54 +0000 (Fri, 02 Sep 2022)");
  script_name("CentOS: Security Advisory for libgudev1-219-78.el7_ (CESA-2022:6160)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2022:6160");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2022-September/073636.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgudev1-219-78.el7_'
  package(s) announced via the CESA-2022:6160 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The systemd packages contain systemd, a system and service manager for
Linux, compatible with the SysV and LSB init scripts. It provides
aggressive parallelism capabilities, uses socket and D-Bus activation for
starting services, offers on-demand starting of daemons, and keeps track of
processes using Linux cgroups. In addition, it supports snapshotting and
restoring of the system state, maintains mount and automount points, and
implements an elaborate transactional dependency-based service control
logic. It can also work as a drop-in replacement for sysvinit.

Security Fix(es):

  * systemd-resolved: use-after-free when dealing with DnsStream in
resolved-dns-stream.c (CVE-2022-2526)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'libgudev1-219-78.el7_' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"libgudev1-219-78.el7", rpm:"libgudev1-219-78.el7~9.7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgudev1-devel-219-78.el7", rpm:"libgudev1-devel-219-78.el7~9.7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-219-78.el7", rpm:"systemd-219-78.el7~9.7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel-219-78.el7", rpm:"systemd-devel-219-78.el7~9.7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-journal-gateway-219-78.el7", rpm:"systemd-journal-gateway-219-78.el7~9.7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-libs-219-78.el7", rpm:"systemd-libs-219-78.el7~9.7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd-219-78.el7", rpm:"systemd-networkd-219-78.el7~9.7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-python-219-78.el7", rpm:"systemd-python-219-78.el7~9.7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-resolved-219-78.el7", rpm:"systemd-resolved-219-78.el7~9.7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysv-219-78.el7", rpm:"systemd-sysv-219-78.el7~9.7", rls:"CentOS7"))) {
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