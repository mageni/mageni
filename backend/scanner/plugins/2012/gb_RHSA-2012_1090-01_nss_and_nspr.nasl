###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for nss and nspr RHSA-2012:1090-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-July/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870789");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-07-19 10:27:57 +0530 (Thu, 19 Jul 2012)");
  script_cve_id("CVE-2012-0441");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for nss and nspr RHSA-2012:1090-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss and nspr'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"nss and nspr on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Network Security Services (NSS) is a set of libraries designed to support
  the cross-platform development of security-enabled client and server
  applications. Netscape Portable Runtime (NSPR) provides platform
  independence for non-GUI operating system facilities.

  A flaw was found in the way the ASN.1 (Abstract Syntax Notation One)
  decoder in NSS handled zero length items. This flaw could cause the decoder
  to incorrectly skip or replace certain items with a default value, or could
  cause an application to crash if, for example, it received a
  specially-crafted OCSP (Online Certificate Status Protocol) response.
  (CVE-2012-0441)

  It was found that a Certificate Authority (CA) issued a subordinate CA
  certificate to its customer, that could be used to issue certificates for
  any name. This update renders the subordinate CA certificate as untrusted.
  (BZ#798533)

  Note: The BZ#798533 fix only applies to applications using the NSS Builtin
  Object Token. It does not render the certificates untrusted for
  applications that use the NSS library, but do not use the NSS Builtin
  Object Token.

  In addition, the nspr package has been upgraded to upstream version 4.9.1,
  and the nss package has been upgraded to upstream version 3.13.5. These
  updates provide a number of bug fixes and enhancements over the previous
  versions. (BZ#834220, BZ#834219)

  All NSS and NSPR users should upgrade to these updated packages, which
  correct these issues and add these enhancements. After installing the
  update, applications using NSS and NSPR must be restarted for the changes
  to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.9.1~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.9.1~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.9.1~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.13.5~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.13.5~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.13.5~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.13.5~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.13.5~4.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
