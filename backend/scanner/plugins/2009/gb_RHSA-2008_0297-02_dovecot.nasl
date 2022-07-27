###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for dovecot RHSA-2008:0297-02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Dovecot is an IMAP server for Linux and UNIX-like systems, primarily
  written with security in mind.

  A flaw was discovered in the way Dovecot handled the &quot;mail_extra_groups&quot;
  option. An authenticated attacker with local shell access could leverage
  this flaw to read, modify, or delete other users mail that is stored on
  the mail server. (CVE-2008-1199)
  
  This issue did not affect the default Red Hat Enterprise Linux 5 Dovecot
  configuration. This update adds two new configuration options --
  &quot;mail_privileged_group&quot; and &quot;mail_access_groups&quot; -- to minimize the usage
  of additional privileges.
  
  A directory traversal flaw was discovered in Dovecot's zlib plug-in. An
  authenticated user could use this flaw to view other compressed mailboxes
  with the permissions of the Dovecot process. (CVE-2007-2231)
  
  A flaw was found in the Dovecot ACL plug-in. User with only insert
  permissions for a mailbox could use the &quot;COPY&quot; and &quot;APPEND&quot; commands to set
  additional message flags. (CVE-2007-4211)
  
  A flaw was found in a way Dovecot cached LDAP query results in certain
  configurations. This could possibly allow authenticated users to log in as
  a different user who has the same password. (CVE-2007-6598)
  
  As well, this updated package fixes the following bugs:
  
  * configuring &quot;userdb&quot; and &quot;passdb&quot; to use LDAP caused Dovecot to hang. A
  segmentation fault may have occurred. In this updated package, using an
  LDAP backend for &quot;userdb&quot; and &quot;passdb&quot; no longer causes Dovecot to hang.
  
  * the Dovecot &quot;login_process_size&quot; limit was configured for 32-bit systems.
  On 64-bit systems, when Dovecot was configured to use either IMAP or POP3,
  the log in processes crashed with out-of-memory errors. Errors such as the
  following were logged:
  
  pop3-login: pop3-login: error while loading shared libraries:
  libsepol.so.1: failed to map segment from shared object: Cannot allocate
  memory
  
  In this updated package, the &quot;login_process_size&quot; limit is correctly
  configured on 64-bit systems, which resolves this issue.
  
  Note: this updated package upgrades dovecot to version 1.0.7. For
  further details, refer to the Dovecot changelog:
  <a  rel= &qt nofollow &qt  href= &qt http://koji.fedoraproject.org/koji/buildinfo?buildID=23397 &qt >http://koji.fedoraproject.org/koji/buildinfo?buildID=23397</a>
  
  Users of dovecot are advised to upgrade to this updated package, which
  resolves these issues.";

tag_affected = "dovecot on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-May/msg00019.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307452");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2008:0297-02");
  script_cve_id("CVE-2007-2231", "CVE-2007-4211", "CVE-2007-6598", "CVE-2008-1199");
  script_name( "RedHat Update for dovecot RHSA-2008:0297-02");

  script_tag(name:"summary", value:"Check for the Version of dovecot");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~1.0.7~2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-debuginfo", rpm:"dovecot-debuginfo~1.0.7~2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
