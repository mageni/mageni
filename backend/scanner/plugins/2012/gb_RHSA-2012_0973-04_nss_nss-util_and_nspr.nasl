###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for nss, nss-util, and nspr RHSA-2012:0973-04
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-June/msg00038.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870765");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-22 10:26:05 +0530 (Fri, 22 Jun 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for nss, nss-util, and nspr RHSA-2012:0973-04");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss, nss-util, and nspr'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"nss, nss-util, and nspr on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Network Security Services (NSS) is a set of libraries designed to support
  the cross-platform development of security-enabled client and server
  applications. Netscape Portable Runtime (NSPR) provides platform
  independence for non-GUI operating system facilities.

  It was found that a Certificate Authority (CA) issued a subordinate CA
  certificate to its customer, that could be used to issue certificates for
  any name. This update renders the subordinate CA certificate as untrusted.
  (BZ#798533)

  Note: This fix only applies to applications using the NSS Builtin Object
  Token. It does not render the certificates untrusted for applications that
  use the NSS library, but do not use the NSS Builtin Object Token.

  The nspr package has been upgraded to upstream version 4.9, which provides
  a number of bug fixes and enhancements over the previous version.
  (BZ#799193)

  The nss-util package has been upgraded to upstream version 3.13.3, which
  provides a number of bug fixes and enhancements over the previous version.
  (BZ#799192)

  The nss package has been upgraded to upstream version 3.13.3, which
  provides numerous bug fixes and enhancements over the previous version. In
  particular, SSL 2.0 is now disabled by default, support for SHA-224 has
  been added, PORT_ErrorToString and PORT_ErrorToName now return the error
  message and symbolic name of an NSS error code, and NSS_GetVersion now
  returns the NSS version string. (BZ#744070)

  These updated nss, nss-util, and nspr packages also provide fixes for the
  following bugs:

  * A PEM module internal function did not clean up memory when detecting a
  non-existent file name. Consequently, memory leaks in client code occurred.
  The code has been improved to deallocate such temporary objects and as a
  result the reported memory leakage is gone. (BZ#746632)

  * Recent changes to NSS re-introduced a problem where applications could
  not use multiple SSL client certificates in the same process. Therefore,
  any attempt to run commands that worked with multiple SSL client
  certificates, such as the 'yum repolist' command, resulted in a
  re-negotiation handshake failure. With this update, a revised patch
  correcting this problem has been applied to NSS, and using multiple SSL
  client certificates in the same process is now possible again. (BZ#761086)

  * The PEM module did not fully initialize newly constructed objects with
  function pointers set to NULL. Consequ ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.9~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.9~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.9~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.13.3~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.13.3~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.13.3~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.13.3~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.13.3~6.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.13.3~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util-debuginfo", rpm:"nss-util-debuginfo~3.13.3~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.13.3~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
