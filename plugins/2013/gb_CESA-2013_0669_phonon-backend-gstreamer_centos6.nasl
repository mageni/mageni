###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for phonon-backend-gstreamer CESA-2013:0669 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019662.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881696");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-22 10:40:44 +0530 (Fri, 22 Mar 2013)");
  script_cve_id("CVE-2013-0254");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_name("CentOS Update for phonon-backend-gstreamer CESA-2013:0669 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phonon-backend-gstreamer'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"phonon-backend-gstreamer on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Qt is a software toolkit that simplifies the task of writing and
  maintaining GUI (Graphical User Interface) applications for the X Window
  System.

  It was discovered that the QSharedMemory class implementation of the Qt
  toolkit created shared memory segments with insecure permissions. A local
  attacker could use this flaw to read or alter the contents of a particular
  shared memory segment, possibly leading to their ability to obtain
  sensitive information or influence the behavior of a process that is using
  the shared memory segment. (CVE-2013-0254)

  Red Hat would like to thank the Qt project for reporting this issue.
  Upstream acknowledges Tim Brown and Mark Lowe of Portcullis Computer
  Security Ltd. as the original reporters.

  Users of Qt should upgrade to these updated packages, which contain a
  backported patch to correct this issue. All running applications linked
  against Qt libraries must be restarted for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"phonon-backend-gstreamer", rpm:"phonon-backend-gstreamer~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt", rpm:"qt~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-demos", rpm:"qt-demos~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-devel", rpm:"qt-devel~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-doc", rpm:"qt-doc~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-examples", rpm:"qt-examples~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-mysql", rpm:"qt-mysql~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-odbc", rpm:"qt-odbc~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-postgresql", rpm:"qt-postgresql~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-sqlite", rpm:"qt-sqlite~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qt-x11", rpm:"qt-x11~4.6.2~26.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
