###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2292-01_gnutls.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for gnutls RHSA-2017:2292-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871850");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:46:27 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2016-7444", "CVE-2017-5334", "CVE-2017-5335", "CVE-2017-5336",
                "CVE-2017-5337", "CVE-2017-7507", "CVE-2017-7869");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for gnutls RHSA-2017:2292-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The gnutls packages provide the GNU
  Transport Layer Security (GnuTLS) library, which implements cryptographic
  algorithms and protocols such as SSL, TLS, and DTLS. The following packages have
  been upgraded to a later upstream version: gnutls (3.3.26). (BZ#1378373)
  Security Fix(es): * A double-free flaw was found in the way GnuTLS parsed
  certain X.509 certificates with Proxy Certificate Information extension. An
  attacker could create a specially-crafted certificate which, when processed by
  an application compiled against GnuTLS, could cause that application to crash.
  (CVE-2017-5334) * Multiple flaws were found in the way gnutls processed OpenPGP
  certificates. An attacker could create specially crafted OpenPGP certificates
  which, when parsed by gnutls, would cause it to crash. (CVE-2017-5335,
  CVE-2017-5336, CVE-2017-5337, CVE-2017-7869) * A null pointer dereference flaw
  was found in the way GnuTLS processed ClientHello messages with status_request
  extension. A remote attacker could use this flaw to cause an application
  compiled with GnuTLS to crash. (CVE-2017-7507) * A flaw was found in the way
  GnuTLS validated certificates using OCSP responses. This could falsely report a
  certificate as valid under certain circumstances. (CVE-2016-7444) The
  CVE-2017-7507 issue was discovered by Hubert Kario (Red Hat QE BaseOS Security
  team). Additional Changes: For detailed information on changes in this release,
  see the Red Hat Enterprise Linux 7.4 Release Notes linked from the References
  section.");
  script_tag(name:"affected", value:"gnutls on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00002.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.3.26~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-c++", rpm:"gnutls-c++~3.3.26~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-dane", rpm:"gnutls-dane~3.3.26~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~3.3.26~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~3.3.26~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~3.3.26~9.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}