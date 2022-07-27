###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0322_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for gnutls SUSE-SU-2014:0322-1 (gnutls)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850991");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 16:15:41 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2009-5138", "CVE-2013-1619", "CVE-2013-2116", "CVE-2014-0092");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for gnutls SUSE-SU-2014:0322-1 (gnutls)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The GnuTLS library received a critical security fix and
  other updates:

  * CVE-2014-0092: The X.509 certificate verification had
  incorrect error handling, which could lead to broken
  certificates marked as being valid.

  * CVE-2009-5138: A verification problem in handling V1
  certificates could also lead to V1 certificates incorrectly
  being handled.

  * CVE-2013-2116: The _gnutls_ciphertext2compressed
  function in lib/gnutls_cipher.c in GnuTLS allowed remote
  attackers to cause a denial of service (buffer over-read
  and crash) via a crafted padding length.

  * CVE-2013-1619: Timing attacks against hashing of
  padding was fixed which might have allowed disclosure of
  keys. (Lucky13 attack).

  Also the following non-security bugs have been fixed:

  * gnutls doesn't like root CAs without Basic
  Constraints. Permit V1 Certificate Authorities properly
  (bnc#760265)

  * memory leak in PSK authentication (bnc#835760)");

  script_tag(name:"affected", value:"gnutls on SUSE Linux Enterprise Server 11 SP1 LTSS");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP1")
{

  if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.4.1~24.39.49.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls-extra26", rpm:"libgnutls-extra26~2.4.1~24.39.49.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls26", rpm:"libgnutls26~2.4.1~24.39.49.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls26-32bit", rpm:"libgnutls26-32bit~2.4.1~24.39.49.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
