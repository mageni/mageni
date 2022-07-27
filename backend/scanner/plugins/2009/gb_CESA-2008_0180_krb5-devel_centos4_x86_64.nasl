###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for krb5-devel CESA-2008:0180 centos4 x86_64
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
  arbitrary code using malformed or truncated Kerberos v4 protocol
  requests. (CVE-2008-0062, CVE-2008-0063)
  
  This issue only affected krb5kdc with Kerberos v4 protocol compatibility
  enabled, which is the default setting on Red Hat Enterprise Linux 4.
  Kerberos v4 protocol support can be disabled by adding &quot;v4_mode=none&quot;
  (without the quotes) to the &quot;[kdcdefaults]&quot; section of
  /var/kerberos/krb5kdc/kdc.conf.
  
  Red Hat would like to thank MIT for reporting these issues.
  
  A double-free flaw was discovered in the GSSAPI library used by MIT
  Kerberos. This flaw could possibly cause a crash of the application using
  the GSSAPI library. (CVE-2007-5971)
  
  All krb5 users are advised to update to these erratum packages which
  contain backported fixes to correct these issues.";

tag_affected = "krb5-devel on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-March/014769.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311786");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:36:45 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063");
  script_name( "CentOS Update for krb5-devel CESA-2008:0180 centos4 x86_64");

  script_tag(name:"summary", value:"Check for the Version of krb5-devel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.3.4~54.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.3.4~54.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.3.4~54.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.3.4~54.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.3.4~54.el4_6.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
