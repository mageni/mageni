###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libvirt CESA-2013:1272 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.881796");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-09-24 11:45:19 +0530 (Tue, 24 Sep 2013)");
  script_cve_id("CVE-2013-4296", "CVE-2013-4311");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for libvirt CESA-2013:1272 centos6");

  script_tag(name:"affected", value:"libvirt on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

libvirt invokes the PolicyKit pkcheck utility to handle authorization. A
race condition was found in the way libvirt used this utility, allowing a
local user to bypass intended PolicyKit authorizations or execute arbitrary
commands with root privileges. (CVE-2013-4311)

Note: With this update, libvirt has been rebuilt to communicate with
PolicyKit via a different API that is not vulnerable to the race condition.
The polkit RHSA-2013:1270 advisory must also be installed to fix the
CVE-2013-4311 issue.

An invalid free flaw was found in libvirtd's
remoteDispatchDomainMemoryStats function. An attacker able to establish a
read-only connection to libvirtd could use this flaw to crash libvirtd.
(CVE-2013-4296)

The CVE-2013-4296 issue was discovered by Daniel P. Berrange of Red Hat.

This update also fixes the following bugs:

  * Prior to this update, the libvirtd daemon leaked memory in the
virCgroupMoveTask() function. A fix has been provided which prevents
libvirtd from incorrect management of memory allocations. (BZ#984556)

  * Previously, the libvirtd daemon was accessing one byte before the array
in the virCgroupGetValueStr() function. This bug has been fixed and
libvirtd now stays within the array bounds. (BZ#984561)

  * When migrating, libvirtd leaked the migration URI (Uniform Resource
Identifier) on destination. A patch has been provided to fix this bug and
the migration URI is now freed correctly. (BZ#984578)

  * Updating a network interface using virDomainUpdateDeviceFlags API failed
when a boot order was set for that interface. The update failed even if the
boot order was set in the provided device XML. The
virDomainUpdateDeviceFlags API has been fixed to correctly parse the boot
order specification from the provided device XML and updating network
interfaces with boot orders now works as expected. (BZ#1003934)

Users of libvirt are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
updated packages, libvirtd will be restarted automatically.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-September/019948.html");
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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~18.el6_4.14", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~18.el6_4.14", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~18.el6_4.14", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~18.el6_4.14", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.10.2~18.el6_4.14", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
