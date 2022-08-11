###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for rpm CESA-2012:0451 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-April/018550.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881091");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:07:08 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for rpm CESA-2012:0451 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"rpm on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The RPM Package Manager (RPM) is a command-line driven package management
  system capable of installing, uninstalling, verifying, querying, and
  updating software packages.

  Multiple flaws were found in the way RPM parsed package file headers. An
  attacker could create a specially-crafted RPM package that, when its
  package header was accessed, or during package signature verification,
  could cause an application using the RPM library (such as the rpm command
  line tool, or the yum and up2date package managers) to crash or,
  potentially, execute arbitrary code. (CVE-2012-0060, CVE-2012-0061,
  CVE-2012-0815)

  Note: Although an RPM package can, by design, execute arbitrary code when
  installed, this issue would allow a specially-crafted RPM package to
  execute arbitrary code before its digital signature has been verified.
  Package downloads from the Red Hat Network are protected by the use of a
  secure HTTPS connection in addition to the RPM package signature checks.

  All RPM users should upgrade to these updated packages, which contain a
  backported patch to correct these issues. All running applications linked
  against the RPM library must be restarted for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.8.0~19.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-apidocs", rpm:"rpm-apidocs~4.8.0~19.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-build", rpm:"rpm-build~4.8.0~19.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-cron", rpm:"rpm-cron~4.8.0~19.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-devel", rpm:"rpm-devel~4.8.0~19.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-libs", rpm:"rpm-libs~4.8.0~19.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpm-python", rpm:"rpm-python~4.8.0~19.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
