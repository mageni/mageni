###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1183_2.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for OpenSSL SUSE-SU-2015:1183-2 (OpenSSL)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851044");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 18:53:41 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2015-1789", "CVE-2015-1790", "CVE-2015-4000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for OpenSSL SUSE-SU-2015:1183-2 (OpenSSL)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenSSL'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OpenSSL was updated to fix several security issues.

  * CVE-2015-4000: The Logjam Attack ( weakdh.org ) has been addressed
  by rejecting connections with DH parameters shorter than 1024 bits.
  We now also generate 2048-bit DH parameters by default.

  * CVE-2015-1789: An out-of-bounds read in X509_cmp_time was fixed.

  * CVE-2015-1790: A PKCS7 decoder crash with missing EnvelopedContent
  was fixed.

  * fixed a timing side channel in RSA decryption (bnc#929678)

  Additional changes:

  * In the default SSL cipher string EXPORT ciphers are now disabled.
  This will only get active if applications get rebuilt and actually
  use this string. (bnc#931698)");

  script_tag(name:"affected", value:"OpenSSL on SUSE Linux Enterprise Desktop 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED11.0SP3")
{

  if ((res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~146.22.31.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~146.22.31.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}