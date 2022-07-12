###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssh CESA-2013:0519 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019458.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881646");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-12 09:59:37 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2012-5536");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for openssh CESA-2013:0519 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"openssh on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"OpenSSH is OpenBSD's Secure Shell (SSH) protocol implementation. These
  packages include the core files necessary for the OpenSSH client and
  server.

  Due to the way the pam_ssh_agent_auth PAM module was built in Red Hat
  Enterprise Linux 6, the glibc's error() function was called rather than the
  intended error() function in pam_ssh_agent_auth to report errors. As these
  two functions expect different arguments, it was possible for an attacker
  to cause an application using pam_ssh_agent_auth to crash, disclose
  portions of its memory or, potentially, execute arbitrary code.
  (CVE-2012-5536)

  Note that the pam_ssh_agent_auth module is not used in Red Hat Enterprise
  Linux 6 by default.

  This update also fixes the following bugs:

  * All possible options for the new RequiredAuthentications directive were
  not documented in the sshd_config man page. This update improves the man
  page to document all the possible options. (BZ#821641)

  * When stopping one instance of the SSH daemon (sshd), the sshd init script
  (/etc/rc.d/init.d/sshd) stopped all sshd processes regardless of the PID of
  the processes. This update improves the init script so that it only kills
  processes with the relevant PID. As a result, the init script now works
  more reliably in a multi-instance environment. (BZ#826720)

  * Due to a regression, the ssh-copy-id command returned an exit status code
  of zero even if there was an error in copying the key to a remote host.
  With this update, a patch has been applied and ssh-copy-id now returns a
  non-zero exit code if there is an error in copying the SSH certificate to a
  remote host. (BZ#836650)

  * When SELinux was disabled on the system, no on-disk policy was installed,
  a user account was used for a connection, and no '~/.ssh' configuration was
  present in that user's home directory, the SSH client terminated
  unexpectedly with a segmentation fault when attempting to connect to
  another system. A patch has been provided to address this issue and the
  crashes no longer occur in the described scenario. (BZ#836655)

  * The 'HOWTO' document /usr/share/doc/openssh-ldap-5.3p1/HOWTO.ldap-keys
  incorrectly documented the use of the AuthorizedKeysCommand directive.
  This update corrects the document. (BZ#857760)

  This update also adds the following enhancements:

  * When attempting to enable SSH for use with a Common Access Card (CAC),
  the ssh-agent utility read all the certificates in the card even though
  only the ID certificate was needed. Consequently, if a user entered their
  PIN incorrectly, then t ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~5.3p1~84.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~5.3p1~84.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~5.3p1~84.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~5.3p1~84.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~5.3p1~84.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_ssh_agent_auth", rpm:"pam_ssh_agent_auth~0.9.3~84.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
