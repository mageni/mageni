###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssl CESA-2010:0054 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-January/016483.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880647");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2409", "CVE-2009-4355");
  script_name("CentOS Update for openssl CESA-2010:0054 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"openssl on CentOS 5");
  script_tag(name:"insight", value:"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
  and Transport Layer Security (TLS v1) protocols, as well as a
  full-strength, general purpose cryptography library.

  It was found that the OpenSSL library did not properly re-initialize its
  internal state in the SSL_library_init() function after previous calls to
  the CRYPTO_cleanup_all_ex_data() function, which would cause a memory leak
  for each subsequent SSL connection. This flaw could cause server
  applications that call those functions during reload, such as a combination
  of the Apache HTTP Server, mod_ssl, PHP, and cURL, to consume all available
  memory, resulting in a denial of service. (CVE-2009-4355)

  Dan Kaminsky found that browsers could accept certificates with MD2 hash
  signatures, even though MD2 is no longer considered a cryptographically
  strong algorithm. This could make it easier for an attacker to create a
  malicious certificate that would be treated as trusted by a browser.
  OpenSSL now disables the use of the MD2 algorithm inside signatures by
  default. (CVE-2009-2409)

  All OpenSSL users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. For the update to take effect,
  all services linked to the OpenSSL library must be restarted, or the system
  rebooted.");
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

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~12.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~12.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~12.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
