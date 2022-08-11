###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssh CESA-2012:0884 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018719.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881183");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:36:31 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-5000");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_name("CentOS Update for openssh CESA-2012:0884 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"openssh on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"OpenSSH is OpenBSD's Secure Shell (SSH) protocol implementation. These
  packages include the core files necessary for the OpenSSH client and
  server.

  A denial of service flaw was found in the OpenSSH GSSAPI authentication
  implementation. A remote, authenticated user could use this flaw to make
  the OpenSSH server daemon (sshd) use an excessive amount of memory, leading
  to a denial of service. GSSAPI authentication is enabled by default
  ('GSSAPIAuthentication yes' in '/etc/ssh/sshd_config'). (CVE-2011-5000)

  These updated openssh packages also provide fixes for the following bugs:

  * SSH X11 forwarding failed if IPv6 was enabled and the parameter
  X11UseLocalhost was set to 'no'. Consequently, users could not set X
  forwarding. This update fixes sshd and ssh to correctly bind the port for
  the IPv6 protocol. As a result, X11 forwarding now works as expected with
  IPv6. (BZ#732955)

  * The sshd daemon was killed by the OOM killer when running a stress test.
  Consequently, a user could not log in. With this update, the sshd daemon
  sets its oom_adj value to -17. As a result, sshd is not chosen by OOM
  killer and users are able to log in to solve problems with memory.
  (BZ#744236)

  * If the SSH server is configured with a banner that contains a backslash
  character, then the client will escape it with another '\' character, so it
  prints double backslashes. An upstream patch has been applied to correct
  the problem and the SSH banner is now correctly displayed. (BZ#809619)

  In addition, these updated openssh packages provide the following
  enhancements:

  * Previously, SSH allowed multiple ways of authentication of which only one
  was required for a successful login. SSH can now be set up to require
  multiple ways of authentication. For example, logging in to an SSH-enabled
  machine requires both a passphrase and a public key to be entered. The
  RequiredAuthentications1 and RequiredAuthentications2 options can be
  configured in the /etc/ssh/sshd_config file to specify authentications that
  are required for a successful login. For example, to set key and password
  authentication for SSH version 2, type:

  echo 'RequiredAuthentications2 publickey, password' >> /etc/ssh/sshd_config

  For more information on the aforementioned /etc/ssh/sshd_config options,
  refer to the sshd_config man page. (BZ#657378)

  * Previously, OpenSSH could use the Advanced Encryption Standard New
  Instructions (AES-NI) instruction set only with the AES Cipher-block
  chaining (CBC) cipher. This update adds  ...

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

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~5.3p1~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~5.3p1~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~5.3p1~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~5.3p1~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~5.3p1~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_ssh_agent_auth", rpm:"pam_ssh_agent_auth~0.9~81.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
