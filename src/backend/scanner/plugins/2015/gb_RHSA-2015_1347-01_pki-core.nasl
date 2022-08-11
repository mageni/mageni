###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for pki-core RHSA-2015:1347-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871409");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2012-2662");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-07-23 06:26:55 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for pki-core RHSA-2015:1347-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'pki-core'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Red Hat Certificate System is an enterprise software system designed to
manage enterprise public key infrastructure (PKI) deployments. PKI Core
contains fundamental packages required by Red Hat Certificate System, which
comprise the Certificate Authority (CA) subsystem.

Multiple cross-site scripting flaws were discovered in the Red Hat
Certificate System Agent and End Entity pages. An attacker could use these
flaws to perform a cross-site scripting (XSS) attack against victims using
the Certificate System's web interface. (CVE-2012-2662)

This update also fixes the following bugs:

  * Previously, pki-core required the SSL version 3 (SSLv3) protocol ranges
to communicate with the 389-ds-base packages. However, recent changes to
389-ds-base disabled the default use of SSLv3 and enforced using protocol
ranges supported by secure protocols, such as the TLS protocol. As a
consequence, the CA failed to install during an Identity Management (IdM)
server installation. This update adds TLS-related parameters to the
server.xml file of the CA to fix this problem, and running the
ipa-server-install command now installs the CA as expected. (BZ#1171848)

  * Previously, the ipa-server-install script failed when attempting to
configure a stand-alone CA on systems with OpenJDK version 1.8.0 installed.
The pki-core build and runtime dependencies have been modified to use
OpenJDK version 1.7.0 during the stand-alone CA configuration. As a result,
ipa-server-install no longer fails in this situation. (BZ#1212557)

  * Creating a Red Hat Enterprise Linux 7 replica from a Red Hat Enterprise
Linux 6 replica running the CA service sometimes failed in IdM deployments
where the initial Red Hat Enterprise Linux 6 CA master had been removed.
This could cause problems in some situations, such as when migrating from
Red Hat Enterprise Linux 6 to Red Hat Enterprise Linux 7. The bug occurred
due to a problem in a previous version of IdM where the subsystem user,
created during the initial CA server installation, was removed together
with the initial master. This update adds the restore-subsystem-user.py
script that restores the subsystem user in the described situation, thus
enabling administrators to create a Red Hat Enterprise Linux 7 replica in
this scenario. (BZ#1225589)

  * Several Java import statements specify wildcard arguments. However, due
to the use of wildcard arguments in the import statements of the source
code contained in the Red Hat Enterprise Linux 6 maintenance branch, a name
space collision created the potential for an incorrect class  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"pki-core on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00025.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"pki-core-debuginfo", rpm:"pki-core-debuginfo~9.0.3~43.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-native-tools", rpm:"pki-native-tools~9.0.3~43.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-symkey", rpm:"pki-symkey~9.0.3~43.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-ca", rpm:"pki-ca~9.0.3~43.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-common", rpm:"pki-common~9.0.3~43.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-java-tools", rpm:"pki-java-tools~9.0.3~43.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-selinux", rpm:"pki-selinux~9.0.3~43.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-setup", rpm:"pki-setup~9.0.3~43.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-silent", rpm:"pki-silent~9.0.3~43.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-util", rpm:"pki-util~9.0.3~43.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
