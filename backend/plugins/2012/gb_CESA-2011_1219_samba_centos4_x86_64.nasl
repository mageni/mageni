###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for samba CESA-2011:1219 centos4 x86_64
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-August/017709.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881388");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:39:58 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-0547", "CVE-2010-0787", "CVE-2011-1678", "CVE-2011-2522",
                "CVE-2011-2694");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for samba CESA-2011:1219 centos4 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"samba on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Samba is a suite of programs used by machines to share files, printers, and
  other information.

  A cross-site scripting (XSS) flaw was found in the password change page of
  the Samba Web Administration Tool (SWAT). If a remote attacker could trick
  a user, who was logged into the SWAT interface, into visiting a
  specially-crafted URL, it would lead to arbitrary web script execution in
  the context of the user's SWAT session. (CVE-2011-2694)

  It was found that SWAT web pages did not protect against Cross-Site
  Request Forgery (CSRF) attacks. If a remote attacker could trick a user,
  who was logged into the SWAT interface, into visiting a specially-crafted
  URL, the attacker could perform Samba configuration changes with the
  privileges of the logged in user. (CVE-2011-2522)

  A race condition flaw was found in the way the mount.cifs tool mounted CIFS
  (Common Internet File System) shares. If mount.cifs had the setuid bit set,
  a local attacker could conduct a symbolic link attack to trick mount.cifs
  into mounting a share over an arbitrary directory they were otherwise not
  allowed to mount to, possibly allowing them to escalate their privileges.
  (CVE-2010-0787)

  It was found that the mount.cifs tool did not properly handle share or
  directory names containing a newline character. If mount.cifs had the
  setuid bit set, a local attacker could corrupt the mtab (mounted file
  systems table) file via a specially-crafted CIFS share mount request.
  (CVE-2010-0547)

  It was found that the mount.cifs tool did not handle certain errors
  correctly when updating the mtab file. If mount.cifs had the setuid bit
  set, a local attacker could corrupt the mtab file by setting a small file
  size limit before running mount.cifs. (CVE-2011-1678)

  Note: mount.cifs from the samba packages distributed by Red Hat does not
  have the setuid bit set. We recommend that administrators do not manually
  set the setuid bit for mount.cifs.

  Red Hat would like to thank the Samba project for reporting CVE-2011-2694
  and CVE-2011-2522, the Debian Security Team for reporting CVE-2010-0787,
  and Dan Rosenberg for reporting CVE-2011-1678. Upstream acknowledges
  Nobuhiro Tsuji of NTT DATA Security Corporation as the original reporter of
  CVE-2011-2694, Yoshihiro Ishikawa of LAC Co., Ltd. as the original reporter
  of CVE-2011-2522, and the Debian Security Team acknowledges Ronald Volgers
  as the original reporter of CVE-2010-0787.

  Users of Samba are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, the smb service will be restarted automatically.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.33~0.34.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.33~0.34.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.33~0.34.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.33~0.34.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
