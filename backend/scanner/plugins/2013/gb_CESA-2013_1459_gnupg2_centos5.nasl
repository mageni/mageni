###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gnupg2 CESA-2013:1459 centos5
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
  script_oid("1.3.6.1.4.1.25623.1.0.881805");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-10-29 14:49:03 +0530 (Tue, 29 Oct 2013)");
  script_cve_id("CVE-2012-6085", "CVE-2013-4351", "CVE-2013-4402");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("CentOS Update for gnupg2 CESA-2013:1459 centos5");

  script_tag(name:"affected", value:"gnupg2 on CentOS 5");
  script_tag(name:"insight", value:"The GNU Privacy Guard (GnuPG or GPG) is a tool for encrypting data and
creating digital signatures, compliant with the proposed OpenPGP Internet
standard and the S/MIME standard.

A denial of service flaw was found in the way GnuPG parsed certain
compressed OpenPGP packets. An attacker could use this flaw to send
specially crafted input data to GnuPG, making GnuPG enter an infinite loop
when parsing data. (CVE-2013-4402)

It was found that importing a corrupted public key into a GnuPG keyring
database corrupted that keyring. An attacker could use this flaw to trick a
local user into importing a specially crafted public key into their keyring
database, causing the keyring to be corrupted and preventing its further
use. (CVE-2012-6085)

It was found that GnuPG did not properly interpret the key flags in a PGP
key packet. GPG could accept a key for uses not indicated by its holder.
(CVE-2013-4351)

Red Hat would like to thank Werner Koch for reporting the CVE-2013-4402
issue. Upstream acknowledges Taylor R Campbell as the original reporter.

All gnupg2 users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-October/019990.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.0.10~6.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
