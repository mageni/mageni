###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2015:0987 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882184");
  script_version("$Revision: 14058 $");
  script_cve_id("CVE-2015-3331");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-09 11:03:32 +0200 (Tue, 09 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2015:0987 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
  kernel, the core of any Linux operating system.

  * A buffer overflow flaw was found in the way the Linux kernel's Intel
AES-NI instructions optimized version of the RFC4106 GCM mode decryption
functionality handled fragmented packets. A remote attacker could use this
flaw to crash, or potentially escalate their privileges on, a system over a
connection with an active AEC-GCM mode IPSec security association.
(CVE-2015-3331, Important)

This update also fixes the following bugs:

  * Previously, the kernel audit subsystem did not correctly track file path
names which could lead to empty, or '(null)' path names in the PATH audit
records. This update fixes the bug by correctly tracking file path names
and displaying the names in the audit PATH records. (BZ#1197746)

  * Due to a change in the internal representation of field types,
AUDIT_LOGINUID set to -1 (4294967295) by the audit API was asymmetrically
converted to an AUDIT_LOGINUID_SET field with a value of 0, unrecognized by
an older audit API. To fix this bug, the kernel takes note about the way
the rule has been formulated and reports the rule in the originally given
form. As a result, older versions of audit provide a report as expected, in
the AUDIT_LOGINUID field type form, whereas the newer versions can migrate
to the new AUDIT_LOGINUID_SET filed type. (BZ#1197748)

  * The GFS2 file system 'Splice Read' operation, which is used for the
sendfile() function, was not properly allocating a required multi-block
reservation structure in memory. Consequently, when the GFS2 block
allocator was called to assign blocks of data, it attempted to dereference
the structure, which resulted in a kernel panic. With this update, 'Splice
read' operation properly allocates the necessary reservation structure in
memory prior to calling the block allocator, and sendfile() thus works
properly for GFS2. (BZ#1201256)

  * Moving an Open vSwitch (OVS) internal vport to a different net name space
and subsequently deleting that name space led to a kernel panic. This bug
has been fixed by removing the OVS internal vport at net name space
deletion. (BZ#1202357)

  * Previously, the kernel audit subsystem was not correctly handling file
and directory moves, leading to audit records that did not match the audit
file watches. This fix correctly handles moves such that the audit file
watches work correctly. (BZ#1202358)

  * Due to a regression, the crypto adapter could not be set online. A patch
has been provided that fixes the device registration process so that the
device can be used also before the registration process is completed, thus
fixing ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-May/021138.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.4.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
