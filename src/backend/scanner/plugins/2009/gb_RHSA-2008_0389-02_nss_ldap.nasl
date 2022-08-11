###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for nss_ldap RHSA-2008:0389-02
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
tag_insight = "The nss_ldap package contains the nss_ldap and pam_ldap modules. The
  nss_ldap module is a plug-in which allows applications to retrieve
  information about users and groups from a directory server. The pam_ldap
  module allows PAM-aware applications to use a directory server to verify
  user passwords.

  A race condition was discovered in nss_ldap which affected certain
  applications which make LDAP connections, such as Dovecot. This could cause
  nss_ldap to answer a request for information about one user with
  information about a different user. (CVE-2007-5794)
  
  In addition, these updated packages fix the following bugs:
  
  * a build error prevented the nss_ldap module from being able to use DNS to
  discover the location of a directory server. For example, when the
  /etc/nsswitch.conf configuration file was configured to use &quot;ldap&quot;, but no
  &quot;host&quot; or &quot;uri&quot; option was configured in the /etc/ldap.conf configuration
  file, no directory server was contacted, and no results were returned.
  
  * the &quot;port&quot; option in the /etc/ldap.conf configuration file on client
  machines was ignored. For example, if a directory server which you were
  attempting to use was listening on a non-default port (i.e. not ports 389
  or 636), it was only possible to use that directory server by including the
  port number in the &quot;uri&quot; option. In this updated package, the &quot;port&quot; option
  works as expected.
  
  * pam_ldap failed to change an expired password if it had to follow a
  referral to do so, which could occur, for example, when using a slave
  directory server in a replicated environment. An error such as the
  following occurred after entering a new password: &quot;LDAP password
  information update failed: Can't contact LDAP server Insufficient 'write'
  privilege to the 'userPassword' attribute&quot;
  
  This has been resolved in this updated package.
  
  * when the &quot;pam_password exop_send_old&quot; password-change method was
  configured in the /etc/ldap.conf configuration file, a logic error in the
  pam_ldap module caused client machines to attempt to change a user's
  password twice. First, the pam_ldap module attempted to change the password
  using the &quot;exop&quot; request, and then again using an LDAP modify request.
  
  * on Red Hat Enterprise Linux 5.1, rebuilding nss_ldap-253-5.el5 when the
  krb5-*-1.6.1-17.el5 packages were installed failed due to an error such as
  the following:
  
  	+ /builddir/build/SOURCES/dlopen.sh ./nss_ldap-253/nss_ldap.so
  	dlopen() of &quot;././nss_l ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "nss_ldap on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-May/msg00022.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311666");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name: "RHSA", value: "2008:0389-02");
  script_cve_id("CVE-2007-5794");
  script_name( "RedHat Update for nss_ldap RHSA-2008:0389-02");

  script_tag(name:"summary", value:"Check for the Version of nss_ldap");
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

  if ((res = isrpmvuln(pkg:"nss_ldap", rpm:"nss_ldap~253~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss_ldap-debuginfo", rpm:"nss_ldap-debuginfo~253~12.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
