###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openssh RHSA-2015:2088-06
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
  script_oid("1.3.6.1.4.1.25623.1.0.871506");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:27:06 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for openssh RHSA-2015:2088-06");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSH is OpenBSD's SSH (Secure Shell)
protocol implementation. These packages include the core files necessary for both
the OpenSSH client and server.

A flaw was found in the way OpenSSH handled PAM authentication when using
privilege separation. An attacker with valid credentials on the system and
able to fully compromise a non-privileged pre-authentication process using
a different flaw could use this flaw to authenticate as other users.
(CVE-2015-6563)

A use-after-free flaw was found in OpenSSH. An attacker able to fully
compromise a non-privileged pre-authentication process using a different
flaw could possibly cause sshd to crash or execute arbitrary code with
root privileges. (CVE-2015-6564)

It was discovered that the OpenSSH sshd daemon did not check the list of
keyboard-interactive authentication methods for duplicates. A remote
attacker could use this flaw to bypass the MaxAuthTries limit, making it
easier to perform password guessing attacks. (CVE-2015-5600)

It was found that the OpenSSH ssh-agent, a program to hold private keys
used for public key authentication, was vulnerable to password guessing
attacks. An attacker able to connect to the agent could use this flaw to
conduct a brute-force attack to unlock keys in the ssh-agent. (BZ#1238238)

This update fixes the following bugs:

  * Previously, the sshd_config(5) man page was misleading and could thus
confuse the user. This update improves the man page text to clearly
describe the AllowGroups feature. (BZ#1150007)

  * The limit for the function for restricting the number of files listed
using the wildcard character (*) that prevents the Denial of Service (DoS)
for both server and client was previously set too low. Consequently, the
user reaching the limit was prevented from listing a directory with a large
number of files over Secure File Transfer Protocol (SFTP). This update
increases the aforementioned limit, thus fixing this bug. (BZ#1160377)

  * When the ForceCommand option with a pseudoterminal was used and the
MaxSession option was set to '2', multiplexed SSH connections did not work
as expected. After the user attempted to open a second multiplexed
connection, the attempt failed if the first connection was still open. This
update modifies OpenSSH to issue only one audit message per session, and
the user is thus able to open two multiplexed connections in this
situation. (BZ#1199112)

  * The ssh-copy-id utility failed if the account on the remote server did
not use an sh-like shell. Remote commands have been modified to run in an
sh-like shell, and ssh-copy-id now works also with non-sh-like she ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"openssh on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00018.html");
  script_tag(name:"solution_type", value:"VendorFix");
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

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6.1p1~22.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.6.1p1~22.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~6.6.1p1~22.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~6.6.1p1~22.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~6.6.1p1~22.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~6.6.1p1~22.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
