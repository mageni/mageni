###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openldap CESA-2012:1151 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-August/018793.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881467");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-09 10:21:35 +0530 (Thu, 09 Aug 2012)");
  script_cve_id("CVE-2012-2668");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for openldap CESA-2012:1151 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"openldap on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
  Protocol) applications and development tools.

  It was found that the OpenLDAP server daemon ignored olcTLSCipherSuite
  settings. This resulted in the default cipher suite always being used,
  which could lead to weaker than expected ciphers being accepted during
  Transport Layer Security (TLS) negotiation with OpenLDAP clients.
  (CVE-2012-2668)

  This update also fixes the following bug:

  * When the smbk5pwd overlay was enabled in an OpenLDAP server, and a user
  changed their password, the Microsoft NT LAN Manager (NTLM) and Microsoft
  LAN Manager (LM) hashes were not computed correctly. This led to the
  sambaLMPassword and sambaNTPassword attributes being updated with incorrect
  values, preventing the user logging in using a Windows-based client or a
  Samba client.

  With this update, the smbk5pwd overlay is linked against OpenSSL. As such,
  the NTLM and LM hashes are computed correctly, and password changes work as
  expected when using smbk5pwd. (BZ#844428)

  Users of OpenLDAP are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing this
  update, the OpenLDAP daemons will be restarted automatically.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.23~26.el6_3.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.23~26.el6_3.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.4.23~26.el6_3.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.23~26.el6_3.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.4.23~26.el6_3.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
