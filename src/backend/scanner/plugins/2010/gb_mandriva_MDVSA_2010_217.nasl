###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for dovecot MDVSA-2010:217 (dovecot)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "Multiple vulnerabilities was discovered and corrected in dovecot:

  Dovecot 1.2.x before 1.2.15 and 2.0.x before 2.0.beta2 grants the admin
  permission to the owner of each mailbox in a non-public namespace,
  which might allow remote authenticated users to bypass intended access
  restrictions by changing the ACL of a mailbox, as demonstrated by a
  symlinked shared mailbox (CVE-2010-3779).
  
  Dovecot 1.2.x before 1.2.15 allows remote authenticated users to
  cause a denial of service (master process outage) by simultaneously
  disconnecting many (1) IMAP or (2) POP3 sessions (CVE-2010-3780).
  
  The ACL plugin in Dovecot 1.2.x before 1.2.13 propagates INBOX ACLs to
  newly created mailboxes in certain configurations, which might allow
  remote attackers to read mailboxes that have unintended weak ACLs
  (CVE-2010-3304).
  
  plugins/acl/acl-backend-vfile.c in Dovecot 1.2.x before 1.2.15
  and 2.0.x before 2.0.5 interprets an ACL entry as a directive to
  add to the permissions granted by another ACL entry, instead of a
  directive to replace the permissions granted by another ACL entry,
  in certain circumstances involving the private namespace of a user,
  which allows remote authenticated users to bypass intended access
  restrictions via a request to read or modify a mailbox (CVE-2010-3706).
  
  plugins/acl/acl-backend-vfile.c in Dovecot 1.2.x before 1.2.15 and
  2.0.x before 2.0.5 interprets an ACL entry as a directive to add to
  the permissions granted by another ACL entry, instead of a directive
  to replace the permissions granted by another ACL entry, in certain
  circumstances involving more specific entries that occur after less
  specific entries, which allows remote authenticated users to bypass
  intended access restrictions via a request to read or modify a mailbox
  (CVE-2010-3707).
  
  This advisory provides dovecot 1.2.15 which is not vulnerable to
  these issues";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "dovecot on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-10/msg00043.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313421");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-16 14:49:48 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_xref(name: "MDVSA", value: "2010:217");
  script_cve_id("CVE-2010-3779", "CVE-2010-3780", "CVE-2010-3304", "CVE-2010-3706", "CVE-2010-3707");
  script_name("Mandriva Update for dovecot MDVSA-2010:217 (dovecot)");

  script_tag(name: "summary" , value: "Check for the Version of dovecot");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~1.2.15~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~1.2.15~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-gssapi", rpm:"dovecot-plugins-gssapi~1.2.15~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-ldap", rpm:"dovecot-plugins-ldap~1.2.15~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-managesieve", rpm:"dovecot-plugins-managesieve~1.2.15~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-mysql", rpm:"dovecot-plugins-mysql~1.2.15~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-pgsql", rpm:"dovecot-plugins-pgsql~1.2.15~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-sieve", rpm:"dovecot-plugins-sieve~1.2.15~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-sqlite", rpm:"dovecot-plugins-sqlite~1.2.15~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-gssapi", rpm:"dovecot-plugins-gssapi~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-ldap", rpm:"dovecot-plugins-ldap~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-managesieve", rpm:"dovecot-plugins-managesieve~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-mysql", rpm:"dovecot-plugins-mysql~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-pgsql", rpm:"dovecot-plugins-pgsql~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-sieve", rpm:"dovecot-plugins-sieve~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-sqlite", rpm:"dovecot-plugins-sqlite~1.2.15~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
