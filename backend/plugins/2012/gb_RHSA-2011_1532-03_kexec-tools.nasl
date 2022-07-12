###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kexec-tools RHSA-2011:1532-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00007.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870730");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:56:37 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-3588", "CVE-2011-3589", "CVE-2011-3590");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:N/A:N");
  script_name("RedHat Update for kexec-tools RHSA-2011:1532-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kexec-tools'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"kexec-tools on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Kexec allows for booting a Linux kernel from the context of an already
  running kernel.

  Kdump used the SSH (Secure Shell) 'StrictHostKeyChecking=no' option when
  dumping to SSH targets, causing the target kdump server's SSH host key not
  to be checked. This could make it easier for a man-in-the-middle attacker
  on the local network to impersonate the kdump SSH target server and
  possibly gain access to sensitive information in the vmcore dumps.
  (CVE-2011-3588)

  mkdumprd created initrd files with world-readable permissions. A local user
  could possibly use this flaw to gain access to sensitive information, such
  as the private SSH key used to authenticate to a remote server when kdump
  was configured to dump to an SSH target. (CVE-2011-3589)

  mkdumprd included unneeded sensitive files (such as all files from the
  '/root/.ssh/' directory and the host's private SSH keys) in the resulting
  initrd. This could lead to an information leak when initrd files were
  previously created with world-readable permissions. Note: With this update,
  only the SSH client configuration, known hosts files, and the SSH key
  configured via the newly introduced sshkey option in '/etc/kdump.conf' are
  included in the initrd. The default is the key generated when running the
  'service kdump propagate' command, '/root/.ssh/kdump_id_rsa'.
  (CVE-2011-3590)

  Red Hat would like to thank Kevan Carstensen for reporting these issues.

  This update also fixes several bugs and adds various enhancements.
  Space precludes documenting all of these changes in this advisory.
  Documentation for these bug fixes and enhancements will be available
  shortly from the Technical Notes document, linked to in the References
  section.

  All kexec-tools users should upgrade to this updated package, which
  contains backported patches to resolve these issues and add these
  enhancements.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"kexec-tools", rpm:"kexec-tools~2.0.0~209.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kexec-tools-debuginfo", rpm:"kexec-tools-debuginfo~2.0.0~209.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
