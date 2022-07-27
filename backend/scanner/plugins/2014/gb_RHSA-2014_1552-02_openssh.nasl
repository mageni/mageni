###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openssh RHSA-2014:1552-02
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
  script_oid("1.3.6.1.4.1.25623.1.0.871266");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-10-15 06:06:53 +0200 (Wed, 15 Oct 2014)");
  script_cve_id("CVE-2014-2532", "CVE-2014-2653");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("RedHat Update for openssh RHSA-2014:1552-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSH is OpenBSD's SSH (Secure Shell) protocol implementation.
These packages include the core files necessary for both the OpenSSH client
and server.

It was discovered that OpenSSH clients did not correctly verify DNS SSHFP
records. A malicious server could use this flaw to force a connecting
client to skip the DNS SSHFP record check and require the user to perform
manual host verification of the DNS SSHFP record. (CVE-2014-2653)

It was found that OpenSSH did not properly handle certain AcceptEnv
parameter values with wildcard characters. A remote attacker could use this
flaw to bypass intended environment variable restrictions. (CVE-2014-2532)

This update also fixes the following bugs:

  * Based on the SP800-131A information security standard, the generation of
a digital signature using the Digital Signature Algorithm (DSA) with the
key size of 1024 bits and RSA with the key size of less than 2048 bits is
disallowed after the year 2013. After this update, ssh-keygen no longer
generates keys with less than 2048 bits in FIPS mode. However, the sshd
service accepts keys of size 1024 bits as well as larger keys for
compatibility reasons. (BZ#993580)

  * Previously, the openssh utility incorrectly set the oom_adj value to -17
for all of its children processes. This behavior was incorrect because the
children processes were supposed to have this value set to 0. This update
applies a patch to fix this bug and oom_adj is now properly set to 0 for
all children processes as expected. (BZ#1010429)

  * Previously, if the sshd service failed to verify the checksum of an
installed FIPS module using the fipscheck library, the information about
this failure was only provided at the standard error output of sshd. As a
consequence, the user could not notice this message and be uninformed when
a system had not been properly configured for FIPS mode. To fix this bug,
this behavior has been changed and sshd now sends such messages via the
syslog service. (BZ#1020803)

  * When keys provided by the pkcs11 library were removed from the ssh agent
using the 'ssh-add -e' command, the user was prompted to enter a PIN.
With this update, a patch has been applied to allow the user to remove the
keys provided by pkcs11 without the PIN. (BZ#1042519)

In addition, this update adds the following enhancements:

  * With this update, ControlPersist has been added to OpenSSH. The option in
conjunction with the ControlMaster configuration directive specifies that
the master connection remains open in the background  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"openssh on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-October/msg00020.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~5.3p1~104.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~5.3p1~104.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~5.3p1~104.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~5.3p1~104.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~5.3p1~104.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
