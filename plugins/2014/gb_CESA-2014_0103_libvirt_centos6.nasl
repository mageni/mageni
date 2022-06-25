###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libvirt CESA-2014:0103 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881866");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-30 10:44:30 +0530 (Thu, 30 Jan 2014)");
  script_cve_id("CVE-2013-6458", "CVE-2014-1447");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for libvirt CESA-2014:0103 centos6");

  script_tag(name:"affected", value:"libvirt on CentOS 6");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems.
In addition, libvirt provides tools for remote management of
virtualized systems.

A use-after-free flaw was found in the way several libvirt block APIs
handled domain jobs. A remote attacker able to establish a read-only
connection to libvirtd could use this flaw to crash libvirtd or,
potentially, execute arbitrary code with the privileges of the libvirtd
process (usually root). (CVE-2013-6458)

A race condition was found in the way libvirtd handled keepalive
initialization requests when the connection was closed prior to
establishing connection credentials. An attacker able to establish a
read-only connection to libvirtd could use this flaw to crash libvirtd,
resulting in a denial of service. (CVE-2014-1447)

This update also fixes the following bug:

  * A race condition was possible between a thread starting a virtual machine
with a guest agent configured (regular start-up or while migrating) and a
thread that was killing the VM process (or the process crashing). The race
could cause the monitor object to be freed by the thread that killed the VM
process, which was later accessed by the thread that was attempting to
start the VM, resulting in a crash. This issue was fixed by checking the
state of the VM after the attempted connection to the guest agent  if the
VM in the meantime exited, no other operations are attempted. (BZ#1055578)

All libvirt users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
updated packages, libvirtd will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-January/020125.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~29.el6_5.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~29.el6_5.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~29.el6_5.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~29.el6_5.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.10.2~29.el6_5.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
