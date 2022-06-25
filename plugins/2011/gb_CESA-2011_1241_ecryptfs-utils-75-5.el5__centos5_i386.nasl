###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ecryptfs-utils-75-5.el5_ CESA-2011:1241 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-September/017811.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880998");
  script_version("2019-05-01T16:02:02+0000");
  script_tag(name:"last_modification", value:"2019-05-01 16:02:02 +0000 (Wed, 01 May 2019)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1834", "CVE-2011-1835",
                "CVE-2011-1837", "CVE-2011-3145", "CVE-2011-1833");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for ecryptfs-utils-75-5.el5_ CESA-2011:1241 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ecryptfs-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"ecryptfs-utils-75-5.el5_ on CentOS 5");
  script_tag(name:"insight", value:"eCryptfs is a stacked, cryptographic file system. It is transparent to the
  underlying file system and provides per-file granularity. eCryptfs is
  released as a Technology Preview for Red Hat Enterprise Linux 5 and 6.

  The setuid mount.ecryptfs_private utility allows users to mount an eCryptfs
  file system. This utility can only be run by users in the 'ecryptfs' group.

  A race condition flaw was found in the way mount.ecryptfs_private checked
  the permissions of a requested mount point when mounting an encrypted file
  system. A local attacker could possibly use this flaw to escalate their
  privileges by mounting over an arbitrary directory. (CVE-2011-1831)

  A race condition flaw in umount.ecryptfs_private could allow a local
  attacker to unmount an arbitrary file system. (CVE-2011-1832)

  It was found that mount.ecryptfs_private did not handle certain errors
  correctly when updating the mtab (mounted file systems table) file,
  allowing a local attacker to corrupt the mtab file and possibly unmount an
  arbitrary file system. (CVE-2011-1834)

  An insecure temporary file use flaw was found in the ecryptfs-setup-private
  script. A local attacker could use this script to insert their own key that
  will subsequently be used by a new user, possibly giving the attacker
  access to the user's encrypted data if existing file permissions allow
  access. (CVE-2011-1835)

  A race condition flaw in mount.ecryptfs_private could allow a local
  attacker to overwrite arbitrary files. (CVE-2011-1837)

  A race condition flaw in the way temporary files were accessed in
  mount.ecryptfs_private could allow a malicious, local user to make
  arbitrary modifications to the mtab file. (CVE-2011-3145)

  A race condition flaw was found in the way mount.ecryptfs_private checked
  the permissions of the directory to mount. A local attacker could use this
  flaw to mount (and then access) a directory they would otherwise not have
  access to. Note: The fix for this issue is incomplete until a kernel-space
  change is made. Future Red Hat Enterprise Linux 5 and 6 kernel updates
  will correct this issue. (CVE-2011-1833)

  Red Hat would like to thank the Ubuntu Security Team for reporting these
  issues. The Ubuntu Security Team acknowledges Vasiliy Kulikov of Openwall
  and Dan Rosenberg as the original reporters of CVE-2011-1831,
  CVE-2011-1832, and CVE-2011-1833, Dan Rosenberg and Marc Deslauriers as the
  original reporters of CVE-2011-1834, Marc Deslauriers as the original
  reporter of CVE-2011-1835, and Vasiliy Kulikov of Openwall as the original
  reporter of CVE-2011-1837.

  Users of ecryptfs-utils are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"ecryptfs-utils", rpm:"ecryptfs-utils~75-5.el5~7.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ecryptfs-utils-devel", rpm:"ecryptfs-utils-devel~75-5.el5~7.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ecryptfs-utils-gui", rpm:"ecryptfs-utils-gui~75-5.el5~7.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
