###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for nss_ldap RHSA-2008:0715-01
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

  A race condition was discovered in nss_ldap, which affected certain
  applications that make LDAP connections, such as Dovecot. This could cause
  nss_ldap to answer a request for information about one user with the
  information about a different user. (CVE-2007-5794)
  
  As well, this updated package fixes the following bugs:
  
  * in certain situations, on Itanium(R) architectures, when an application
  performed an LDAP lookup for a highly populated group, for example,
  containing more than 150 members, the application crashed, or may have
  caused a segmentation fault. As well, this issue may have caused commands,
  such as &quot;ls&quot;, to return a &quot;ber_free_buf: Assertion&quot; error.
  
  * when an application enumerated members of a netgroup, the nss_ldap
  module returned a successful status result and the netgroup name, even
  when the netgroup did not exist. This behavior was not consistent with
  other modules. In this updated package, nss_ldap no longer returns a
  successful status when the netgroup does not exist.
  
  * in master and slave server environments, with systems that were
  configured to use a read-only directory server, if user log in attempts
  were denied because their passwords had expired, and users attempted to
  immediately change their passwords, the replication server returned an LDAP
  referral, instructing the pam_ldap module to resissue its request to a
  different server; however, the pam_ldap module failed to do so. In these
  situations, an error such as the following occurred:
  
  LDAP password information update failed: Can't contact LDAP server
  Insufficient 'write' privilege to the 'userPassword' attribute of entry
  [entry]
  
  In this updated package, password changes are allowed when binding against
  a slave server, which resolves this issue.
  
  * when a system used a directory server for naming information, and
  &quot;nss_initgroups_ignoreusers root&quot; was configured in &quot;/etc/ldap.conf&quot;,
  dbus-daemon-1 would hang. Running the &quot;service messagebus start&quot; command
  did not start the service, and it did not fail, which would stop the boot
  process if it was not cancelled.
  
  As well, this u ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "nss_ldap on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-July/msg00032.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307051");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name: "RHSA", value: "2008:0715-01");
  script_cve_id("CVE-2007-5794");
  script_name( "RedHat Update for nss_ldap RHSA-2008:0715-01");

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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"nss_ldap", rpm:"nss_ldap~253~5.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nss_ldap-debuginfo", rpm:"nss_ldap-debuginfo~253~5.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
