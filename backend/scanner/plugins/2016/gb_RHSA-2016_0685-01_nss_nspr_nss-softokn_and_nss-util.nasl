###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for nss, nspr, nss-softokn, and nss-util RHSA-2016:0685-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871603");
  script_version("2021-04-19T11:57:41+0000");
  script_tag(name:"last_modification", value:"2021-04-20 10:28:26 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-04-26 05:18:36 +0200 (Tue, 26 Apr 2016)");
  script_cve_id("CVE-2016-1978", "CVE-2016-1979");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for nss, nspr, nss-softokn, and nss-util RHSA-2016:0685-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss, nspr, nss-softokn, and nss-util'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Network Security Services (NSS) is a set
of libraries designed to support the cross-platform development of security-enabled
client and server applications. The nss-util packages provide utilities for use with
the Network Security Services (NSS) libraries. Netscape Portable Runtime (NSPR)
provides platform independence for non-GUI operating system facilities.

The following packages have been upgraded to a newer upstream version: nss
(3.21.0), nss-util (3.21.0), nspr (4.11.0). (BZ#1310581, BZ#1303021,
BZ#1299872)

Security Fix(es):

  * A use-after-free flaw was found in the way NSS handled DHE
(DiffieHellman key exchange) and ECDHE (Elliptic Curve Diffie-Hellman key
exchange) handshake messages. A remote attacker could send a specially
crafted handshake message that, when parsed by an application linked
against NSS, would cause that application to crash or, under certain
special conditions, execute arbitrary code using the permissions of the
user running the application. (CVE-2016-1978)

  * A use-after-free flaw was found in the way NSS processed certain DER
(Distinguished Encoding Rules) encoded cryptographic keys. An attacker
could use this flaw to create a specially crafted DER encoded certificate
which, when parsed by an application compiled against the NSS library,
could cause that application to crash, or execute arbitrary code using the
permissions of the user running the application. (CVE-2016-1979)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Eric Rescorla as the original reporter of
CVE-2016-1978 and Tim Taubert as the original reporter of CVE-2016-1979.

Bug Fix(es):

  * The nss-softokn package has been updated to be compatible with NSS 3.21.
(BZ#1326221)");
  script_tag(name:"affected", value:"nss, nspr, nss-softokn, and nss-util on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:0685-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-April/msg00037.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.11.0~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.11.0~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.11.0~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.21.0~9.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-debuginfo", rpm:"nss-debuginfo~3.21.0~9.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.21.0~9.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn", rpm:"nss-softokn~3.16.2.3~14.2.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-debuginfo", rpm:"nss-softokn-debuginfo~3.16.2.3~14.2.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-devel", rpm:"nss-softokn-devel~3.16.2.3~14.2.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-freebl", rpm:"nss-softokn-freebl~3.16.2.3~14.2.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-softokn-freebl-devel", rpm:"nss-softokn-freebl-devel~3.16.2.3~14.2.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.21.0~9.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.21.0~9.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.21.0~2.2.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util-debuginfo", rpm:"nss-util-debuginfo~3.21.0~2.2.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.21.0~2.2.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
