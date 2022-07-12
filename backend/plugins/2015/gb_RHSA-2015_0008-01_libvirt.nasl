###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libvirt RHSA-2015:0008-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871298");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-01-23 12:55:18 +0100 (Fri, 23 Jan 2015)");
  script_cve_id("CVE-2014-7823");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RedHat Update for libvirt RHSA-2015:0008-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems.
In addition, libvirt provides tools for remote management of
virtualized systems.

It was found that when the VIR_DOMAIN_XML_MIGRATABLE flag was used, the
QEMU driver implementation of the virDomainGetXMLDesc() function could
bypass the restrictions of the VIR_DOMAIN_XML_SECURE flag. A remote
attacker able to establish a read-only connection to libvirtd could use
this flaw to leak certain limited information from the domain XML data.
(CVE-2014-7823)

This issue was discovered by Eric Blake of Red Hat.

This update also fixes the following bugs:

  * In Red Hat Enterprise Linux 6, libvirt relies on the QEMU emulator to
supply the error message when an active commit is attempted. However, with
Red Hat Enterprise Linux 7, QEMU added support for an active commit, but an
additional interaction from libvirt to fully enable active commits is still
missing. As a consequence, attempts to perform an active commit caused
libvirt to become unresponsive. With this update, libvirt has been fixed to
detect an active commit by itself, and now properly declares the feature as
unsupported. As a result, libvirt no longer hangs when an active commit is
attempted and instead produces an error message.

Note that the missing libvirt interaction will be added in Red Hat
Enterprise Linux 7.1, adding full support for active commits. (BZ#1150379)

  * Prior to this update, the libvirt API did not properly check whether a
Discretionary Access Control (DAC) security label is non-NULL before trying
to parse user/group ownership from it. In addition, the DAC security label
of a transient domain that had just finished migrating to another host is
in some cases NULL. As a consequence, when the virDomainGetBlockInfo API
was called on such a domain, the libvirtd daemon sometimes terminated
unexpectedly. With this update, libvirt properly checks DAC labels before
trying to parse them, and libvirtd thus no longer crashes in the described
scenario. (BZ#1171124)

  * If a block copy operation was attempted while another block copy was
already in progress to an explicit raw destination, libvirt previously
stopped regarding the destination as raw. As a consequence, if the
qemu.conf file was edited to allow file format probing, triggering the bug
could allow a malicious guest to bypass sVirt protection by making libvirt
regard the file as non-raw. With this update, libvirt has been fixed to
consistently remember when a block copy destination is raw, and guests can
no longer circum ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"libvirt on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-January/msg00000.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-kvm", rpm:"libvirt-daemon-kvm~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-debuginfo", rpm:"libvirt-debuginfo~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~1.1.1~29.el7_0.4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
