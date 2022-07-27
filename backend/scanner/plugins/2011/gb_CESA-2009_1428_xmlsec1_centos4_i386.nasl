###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for xmlsec1 CESA-2009:1428 centos4 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016129.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880948");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0217");
  script_name("CentOS Update for xmlsec1 CESA-2009:1428 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xmlsec1'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"xmlsec1 on CentOS 4");
  script_tag(name:"insight", value:"The XML Security Library is a C library based on libxml2 and OpenSSL. It
  implements the XML Signature Syntax and Processing and XML Encryption
  Syntax and Processing standards. HMAC is used for message authentication
  using cryptographic hash functions. The HMAC algorithm allows the hash
  output to be truncated (as documented in RFC 2104).

  A missing check for the recommended minimum length of the truncated form of
  HMAC-based XML signatures was found in xmlsec1. An attacker could use this
  flaw to create a specially-crafted XML file that forges an XML signature,
  allowing the attacker to bypass authentication that is based on the XML
  Signature specification. (CVE-2009-0217)

  Users of xmlsec1 should upgrade to these updated packages, which contain
  a backported patch to correct this issue. After installing the updated
  packages, applications that use the XML Security Library must be restarted
  for the update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"xmlsec1", rpm:"xmlsec1~1.2.6~3.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmlsec1-devel", rpm:"xmlsec1-devel~1.2.6~3.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmlsec1-openssl", rpm:"xmlsec1-openssl~1.2.6~3.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmlsec1-openssl-devel", rpm:"xmlsec1-openssl-devel~1.2.6~3.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
