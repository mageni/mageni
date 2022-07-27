###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for krb5 RHSA-2015:2154-07
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
  script_oid("1.3.6.1.4.1.25623.1.0.871493");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:22:41 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2014-5355", "CVE-2015-2694");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for krb5 RHSA-2015:2154-07");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Kerberos is a network authentication system,
which can improve the security of your network by eliminating the insecure practice
of sending passwords over the network in unencrypted form. It allows clients and
servers to authenticate to each other with the help of a trusted third party, the
Kerberos key distribution center (KDC).

It was found that the krb5_read_message() function of MIT Kerberos did not
correctly sanitize input, and could create invalid krb5_data objects.
A remote, unauthenticated attacker could use this flaw to crash a Kerberos
child process via a specially crafted request. (CVE-2014-5355)

A flaw was found in the OTP kdcpreauth module of MIT kerberos.
An unauthenticated remote attacker could use this flaw to bypass the
requires_preauth flag on a client principal and obtain a ciphertext
encrypted in the principal's long-term key. This ciphertext could be used
to conduct an off-line dictionary attack against the user's password.
(CVE-2015-2694)

The krb5 packages have been upgraded to upstream version 1.13.2, which
provides a number of bug fixes and enhancements over the previous version.
(BZ#1203889)

Notably, this update fixes the following bugs:

  * Previously, the RADIUS support (libkrad) in krb5 was sending krb5
authentication for Transmission Control Protocol (TCP) transports multiple
times, accidentally using a code path intended to be used only for
unreliable transport types, for example User Datagram Protocol (UDP)
transports. A patch that fixes the problem by disabling manual retries for
reliable transports, such as TCP, has been applied, and the correct code
path is now used in this situation. (BZ#1251586)

  * Attempts to use Kerberos single sign-on (SSO) to access SAP NetWeaver
systems sometimes failed. The SAP NetWeaver developer trace displayed the
following error message:

    No credentials were supplied, or the credentials were
    unavailable or inaccessible
    Unable to establish the security context

Querying SSO credential lifetime has been modified to trigger credential
acquisition, thus preventing the error from occurring. Now, the user can
successfully use Kerberos SSO for accessing SAP NetWeaver systems.
(BZ#1252454)

All krb5 users are advised to upgrade to these updated packages, which
correct these issues and add these enhancements.");
  script_tag(name:"affected", value:"krb5 on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00026.html");
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

  if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.13.2~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.13.2~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.13.2~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-pkinit", rpm:"krb5-pkinit~1.13.2~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.13.2~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.13.2~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.13.2~10.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
