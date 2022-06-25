###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2019_0201_libgudev1-219-62.el7_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for libgudev1-219-62.el7_ CESA-2019:0201 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882996");
  script_version("$Revision: 14058 $");
  script_cve_id("CVE-2019-3815", "CVE-2018-16864");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-02 04:03:31 +0100 (Sat, 02 Feb 2019)");
  script_name("CentOS Update for libgudev1-219-62.el7_ CESA-2019:0201 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-February/023163.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgudev1-219-62.el7_'
  package(s) announced via the CESA-2019:0201 advisory.");

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

  * systemd: memory leak in journald-server.c introduced by fix for
CVE-2018-16864 (CVE-2019-3815)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.");

  script_tag(name:"affected", value:"libgudev1-219-62.el7_ on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"libgudev1-219-62.el7", rpm:"libgudev1-219-62.el7~6.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgudev1-devel-219-62.el7", rpm:"libgudev1-devel-219-62.el7~6.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-219-62.el7", rpm:"systemd-219-62.el7~6.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-devel-219-62.el7", rpm:"systemd-devel-219-62.el7~6.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-journal-gateway-219-62.el7", rpm:"systemd-journal-gateway-219-62.el7~6.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-libs-219-62.el7", rpm:"systemd-libs-219-62.el7~6.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-networkd-219-62.el7", rpm:"systemd-networkd-219-62.el7~6.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-python-219-62.el7", rpm:"systemd-python-219-62.el7~6.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-resolved-219-62.el7", rpm:"systemd-resolved-219-62.el7~6.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"systemd-sysv-219-62.el7", rpm:"systemd-sysv-219-62.el7~6.3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
