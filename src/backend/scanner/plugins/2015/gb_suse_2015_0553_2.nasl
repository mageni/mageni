###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0553_2.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for compat-openssl098 SUSE-SU-2015:0553-2 (compat-openssl098)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850905");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 13:54:15 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2009-5146", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for compat-openssl098 SUSE-SU-2015:0553-2 (compat-openssl098)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openssl098'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSL was updated to fix various security issues.

  Following security issues were fixed:

  - CVE-2015-0209: A Use After Free following d2i_ECPrivatekey error was
  fixed which could lead to crashes for attacker supplied Elliptic Curve
  keys. This could be exploited over SSL connections with client supplied
  keys.

  - CVE-2015-0286: A segmentation fault in ASN1_TYPE_cmp was fixed that
  could be exploited by attackers when e.g. client authentication is used.
  This could be exploited over SSL connections.

  - CVE-2015-0287: A ASN.1 structure reuse memory corruption was fixed. This
  problem can not be exploited over regular SSL connections, only if
  specific client programs use specific ASN.1 routines.

  - CVE-2015-0288: A X509_to_X509_REQ NULL pointer dereference was fixed,
  which could lead to crashes. This function is not commonly used, and not
  reachable over SSL methods.

  - CVE-2015-0289: Several PKCS7 NULL pointer dereferences were fixed, which
  could lead to crashes of programs using the PKCS7 APIs. The SSL apis do
  not use those by default.

  - CVE-2015-0292: Various issues in base64 decoding were fixed, which could
  lead to crashes with memory corruption, for instance by using attacker
  supplied PEM data.

  - CVE-2015-0293: Denial of service via reachable assert in SSLv2 servers,
  could be used by remote attackers to terminate the server process. Note
  that this requires SSLv2 being allowed, which is not the default.

  - CVE-2009-5146: A memory leak in the TLS hostname extension was fixed,
  which could be used by remote attackers to run SSL services out of
  memory.");
  script_tag(name:"affected", value:"compat-openssl098 on SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"compat-openssl098-debugsource", rpm:"compat-openssl098-debugsource~0.9.8j~73.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~73.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8j~73.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo", rpm:"libopenssl0_9_8-debuginfo~0.9.8j~73.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo-32bit", rpm:"libopenssl0_9_8-debuginfo-32bit~0.9.8j~73.2", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}