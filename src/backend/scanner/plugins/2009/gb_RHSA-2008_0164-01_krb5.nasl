###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for krb5 RHSA-2008:0164-01
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
tag_insight = "Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other through use of symmetric encryption
  and a trusted third party, the KDC.

  A flaw was found in the way the MIT Kerberos Authentication Service and Key
  Distribution Center server (krb5kdc) handled Kerberos v4 protocol packets.
  An unauthenticated remote attacker could use this flaw to crash the
  krb5kdc daemon, disclose portions of its memory, or possibly execute
  arbitrary code using malformed or truncated Kerberos v4 protocol requests.
  (CVE-2008-0062, CVE-2008-0063)
  
  This issue only affected krb5kdc with Kerberos v4 protocol compatibility
  enabled, which is the default setting on Red Hat Enterprise Linux 4.
  Kerberos v4 protocol support can be disabled by adding &quot;v4_mode=none&quot;
  (without the quotes) to the &quot;[kdcdefaults]&quot; section of
  /var/kerberos/krb5kdc/kdc.conf.
  
  Jeff Altman of Secure Endpoints discovered a flaw in the RPC library as
  used by MIT Kerberos kadmind server. An unauthenticated remote attacker
  could use this flaw to crash kadmind or possibly execute arbitrary code.
  This issue only affected systems with certain resource limits configured
  and did not affect systems using default resource limits used by Red Hat
  Enterprise Linux 5. (CVE-2008-0947)
  
  Red Hat would like to thank MIT for reporting these issues.
  
  Multiple memory management flaws were discovered in the GSSAPI library used
  by MIT Kerberos. These flaws could possibly result in use of already freed
  memory or an attempt to free already freed memory blocks (double-free
  flaw), possibly causing a crash or arbitrary code execution.
  (CVE-2007-5901, CVE-2007-5971)
  
  In addition to the security issues resolved above, the following bugs were
  also fixed:
  
  * delegated krb5 credentials were not properly stored when SPNEGO was the
  underlying mechanism during GSSAPI authentication. Consequently,
  applications attempting to copy delegated Kerberos 5 credentials into a
  credential cache received an &quot;Invalid credential was supplied&quot; message
  rather than a copy of the delegated credentials. With this update, SPNEGO
  credentials can be properly searched, allowing applications to copy
  delegated credentials as expected.
  
  * applications can initiate context acceptance (via gss_accept_sec_context)
  without passing a ret_flags value that would indicate that credentials were
  delegated. A delegated credential handle should have been returned in such
  instances. This updated package adds a temp_ret_flag that stores th ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "krb5 on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-March/msg00009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.304645");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0164-01");
  script_cve_id("CVE-2007-5901", "CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
  script_name( "RedHat Update for krb5 RHSA-2008:0164-01");

  script_tag(name:"summary", value:"Check for the Version of krb5");
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

  if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.6.1~17.el5_1.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.1~17.el5_1.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.1~17.el5_1.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.1~17.el5_1.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.1~17.el5_1.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
