###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gnutls CESA-2010:0166 centos5 i386
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
  script_oid("1.3.6.1.4.1.25623.1.0.880630");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2009-2409", "CVE-2009-3555");
  script_name("CentOS Update for gnutls CESA-2010:0166 centos5 i386");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-March/016587.html");
  script_xref(name:"URL", value:"http://kbase.redhat.com/faq/docs/DOC-20491");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"gnutls on CentOS 5");
  script_tag(name:"insight", value:"The GnuTLS library provides support for cryptographic algorithms and for
  protocols such as Transport Layer Security (TLS).

  A flaw was found in the way the TLS/SSL (Transport Layer Security/Secure
  Sockets Layer) protocols handled session renegotiation. A man-in-the-middle
  attacker could use this flaw to prefix arbitrary plain text to a client's
  session (for example, an HTTPS connection to a website). This could force
  the server to process an attacker's request as if authenticated using the
  victim's credentials. This update addresses this flaw by implementing the
  TLS Renegotiation Indication Extension, as defined in RFC 5746.
  (CVE-2009-3555)

  Refer to the linked Knowledgebase article for additional details about
  the CVE-2009-3555 flaw.

  Dan Kaminsky found that browsers could accept certificates with MD2 hash
  signatures, even though MD2 is no longer considered a cryptographically
  strong algorithm. This could make it easier for an attacker to create a
  malicious certificate that would be treated as trusted by a browser. GnuTLS
  now disables the use of the MD2 algorithm inside signatures by default.
  (CVE-2009-2409)

  Users of GnuTLS are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. For the update to take
  effect, all applications linked to the GnuTLS library must be restarted, or
  the system rebooted.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~1.4.1~3.el5_4.8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-devel", rpm:"gnutls-devel~1.4.1~3.el5_4.8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~1.4.1~3.el5_4.8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
