###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for nss and nspr RHSA-2013:1135-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871026");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-08-08 11:30:07 +0530 (Thu, 08 Aug 2013)");
  script_cve_id("CVE-2013-0791", "CVE-2013-1620");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for nss and nspr RHSA-2013:1135-01");


  script_tag(name:"affected", value:"nss and nspr on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"Network Security Services (NSS) is a set of libraries designed to support
the cross-platform development of security-enabled client and server
applications. Netscape Portable Runtime (NSPR) provides platform
independence for non-GUI operating system facilities.

It was discovered that NSS leaked timing information when decrypting
TLS/SSL and DTLS protocol encrypted records when CBC-mode cipher suites
were used. A remote attacker could possibly use this flaw to retrieve plain
text from the encrypted packets by using a TLS/SSL or DTLS server as a
padding oracle. (CVE-2013-1620)

An out-of-bounds memory read flaw was found in the way NSS decoded certain
certificates. If an application using NSS decoded a malformed certificate,
it could cause the application to crash. (CVE-2013-0791)

Red Hat would like to thank the Mozilla project for reporting
CVE-2013-0791. Upstream acknowledges Ambroz Bizjak as the original reporter
of CVE-2013-0791.

This update also fixes the following bugs:

  * A defect in the FreeBL library implementation of the Diffie-Hellman (DH)
protocol previously caused Openswan to drop connections. (BZ#958023)

  * A memory leak in the nssutil_ReadSecmodDB() function has been fixed.
(BZ#986969)

In addition, the nss package has been upgraded to upstream version 3.14.3,
and the nspr package has been upgraded to upstream version 4.9.5. These
updates provide a number of bug fixes and enhancements over the previous
versions. (BZ#949845, BZ#924741)

Note that while upstream NSS version 3.14 prevents the use of certificates
that have an MD5 signature, this erratum includes a patch that allows such
certificates by default. To prevent the use of certificates that have an
MD5 signature, set the 'NSS_HASH_ALG_SUPPORT' environment variable
to '-MD5'.

Users of NSS and NSPR are advised to upgrade to these updated packages,
which fix these issues and add these enhancements. After installing this
update, applications using NSS or NSPR must be restarted for this update to
take effect.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-August/msg00002.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss and nspr'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.9.5~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.9.5~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.9.5~1.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.14.3~6.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.14.3~6.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.14.3~6.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.14.3~6.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.14.3~6.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}