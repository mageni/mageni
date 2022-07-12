###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libvirt CESA-2013:0831 centos6
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
  script_tag(name:"affected", value:"libvirt on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
  virtualization capabilities of Linux and other operating systems. In
  addition, libvirt provides tools for remote management of virtualized
  systems.

  It was found that libvirtd leaked file descriptors when listing all volumes
  for a particular pool. A remote attacker able to establish a read-only
  connection to libvirtd could use this flaw to cause libvirtd to consume all
  available file descriptors, preventing other users from using libvirtd
  services (such as starting a new guest) until libvirtd is restarted.
  (CVE-2013-1962)

  Red Hat would like to thank Edoardo Comar of IBM for reporting this issue.

  This update also fixes the following bugs:

  * Previously, libvirt made control group (cgroup) requests on files that
  it should not have. With older kernels, such nonsensical cgroup requests
  were ignored. However, newer kernels are stricter, resulting in libvirt
  logging spurious warnings and failures to the libvirtd and audit logs. The
  audit log failures displayed by the ausearch tool were similar to the
  following:

  root [date] - failed cgroup allow path rw /dev/kqemu

  With this update, libvirt no longer attempts the nonsensical cgroup
  actions, leaving only valid attempts in the libvirtd and audit logs (making
  it easier to search for real cases of failure). (BZ#958837)

  * Previously, libvirt used the wrong variable when constructing audit
  messages. This led to invalid audit messages, causing ausearch to format
  certain entries as having path=(null)' instead of the correct path. This
  could prevent ausearch from locating events related to cgroup device ACL
  modifications for guests managed by libvirt. With this update, the audit
  messages are generated correctly, preventing loss of audit coverage.
  (BZ#958839)

  All users of libvirt are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. After installing
  the updated packages, libvirtd will be restarted automatically.");
  script_oid("1.3.6.1.4.1.25623.1.0.881735");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-05-17 09:53:55 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2013-1962");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("CentOS Update for libvirt CESA-2013:0831 centos6");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019732.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~18.el6_4.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~18.el6_4.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~18.el6_4.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~18.el6_4.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.10.2~18.el6_4.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
