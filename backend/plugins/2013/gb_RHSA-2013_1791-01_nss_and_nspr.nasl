###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for nss and nspr RHSA-2013:1791-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871091");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-12-17 11:52:36 +0530 (Tue, 17 Dec 2013)");
  script_cve_id("CVE-2013-1739", "CVE-2013-1741", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-5607", "CVE-2013-1620");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for nss and nspr RHSA-2013:1791-01");


  script_tag(name:"affected", value:"nss and nspr on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"Network Security Services (NSS) is a set of libraries designed to support
the cross-platform development of security-enabled client and server
applications. Netscape Portable Runtime (NSPR) provides platform
independence for non-GUI operating system facilities.

A flaw was found in the way NSS handled invalid handshake packets. A remote
attacker could use this flaw to cause a TLS/SSL client using NSS to crash
or, possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2013-5605)

It was found that the fix for CVE-2013-1620 released via RHSA-2013:1135
introduced a regression causing NSS to read uninitialized data when a
decryption failure occurred. A remote attacker could use this flaw to cause
a TLS/SSL server using NSS to crash. (CVE-2013-1739)

An integer overflow flaw was discovered in both NSS and NSPR's
implementation of certification parsing on 64-bit systems. A remote
attacker could use these flaws to cause an application using NSS or NSPR to
crash. (CVE-2013-1741, CVE-2013-5607)

It was discovered that NSS did not reject certificates with incompatible
key usage constraints when validating them while the verifyLog feature was
enabled. An application using the NSS certificate validation API could
accept an invalid certificate. (CVE-2013-5606)

Red Hat would like to thank the Mozilla project for reporting
CVE-2013-1741, CVE-2013-5606, and CVE-2013-5607. Upstream acknowledges
Tavis Ormandy as the original reporter of CVE-2013-1741, Camilo Viecco as
the original reporter of CVE-2013-5606, and Pascal Cuoq, Kamil Dudka, and
Wan-Teh Chang as the original reporters of CVE-2013-5607.

In addition, the nss package has been upgraded to upstream version 3.15.3,
and the nspr package has been upgraded to upstream version 4.10.2.
These updates provide a number of bug fixes and enhancements over the
previous versions. (BZ#1033478, BZ#1020520)

This update also fixes the following bug:

  * The RHBA-2013:1318 update introduced a regression that prevented the use
of certificates that have an MD5 signature. This update fixes this
regression and certificates that have an MD5 signature are once again
supported. To prevent the use of certificates that have an MD5 signature,
set the 'NSS_HASH_ALG_SUPPORT' environment variable to '-MD5'. (BZ#1033499)

Users of NSS and NSPR are advised to upgrade to these updated packages,
which fix these issues and add these enhancements. After installing this
update, applications using NSS or NSPR must be restarted for this update to
take effect.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-December/msg00007.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss and nspr'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.10.2~2.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.10.2~2.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.10.2~2.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.15.3~3.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.15.3~3.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.15.3~3.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.15.3~3.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.15.3~3.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}