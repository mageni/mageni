###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for bind RHSA-2008:0300-02
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
tag_insight = "The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
  Name System (DNS) protocols. BIND includes a DNS server (named); a resolver
  library (routines for applications to use when interfacing with DNS); and
  tools for verifying that the DNS server is operating correctly.

  It was discovered that the bind packages created the &quot;rndc.key&quot; file with
  insecure file permissions. This allowed any local user to read the content
  of this file. A local user could use this flaw to control some aspects of
  the named daemon by using the rndc utility, for example, stopping the named
  daemon. This problem did not affect systems with the bind-chroot package
  installed. (CVE-2007-6283)
  
  A buffer overflow flaw was discovered in the &quot;inet_network()&quot; function, as
  implemented by libbind. An attacker could use this flaw to crash an
  application calling this function, with an argument provided from an
  untrusted source. (CVE-2008-0122)
  
  As well, these updated packages fix the following bugs:
  
  * when using an LDAP backend, missing function declarations caused
  segmentation faults, due to stripped pointers on machines where pointers
  are longer than integers.
  
  * starting named may have resulted in named crashing, due to a race
  condition during D-BUS connection initialization. This has been resolved in
  these updated packages.
  
  * the named init script returned incorrect error codes, causing the
  &quot;status&quot; command to return an incorrect status. In these updated packages,
  the named init script is Linux Standard Base (LSB) compliant.
  
  * in these updated packages, the &quot;rndc [command] [zone]&quot; command, where
  [command] is an rndc command, and [zone] is the specified zone, will find
  the [zone] if the zone is unique to all views.
  
  * the default named log rotation script did not work correctly when using
  the bind-chroot package. In these updated packages, installing
  bind-chroot creates the symbolic link &quot;/var/log/named.log&quot;, which points
  to &quot;/var/named/chroot/var/log/named.log&quot;, which resolves this issue.
  
  * a previous bind update incorrectly changed the permissions on the
  &quot;/etc/openldap/schema/dnszone.schema&quot; file to mode 640, instead of mode
  644, which resulted in OpenLDAP not being able to start. In these updated
  packages, the permissions are correctly set to mode 644.
  
  * the &quot;checkconfig&quot; parameter was missing in the named usage report. For
  example, running the &quot;service named&quot; command did not return &quot;checkconfi ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "bind on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-May/msg00020.html");
  script_oid("1.3.6.1.4.1.25623.1.0.304997");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0300-02");
  script_cve_id("CVE-2007-6283", "CVE-2008-0122");
  script_name( "RedHat Update for bind RHSA-2008:0300-02");

  script_tag(name:"summary", value:"Check for the Version of bind");
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

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.3.4~6.P1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.3.4~6.P1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.3.4~6.P1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.3.4~6.P1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libbind-devel", rpm:"bind-libbind-devel~9.3.4~6.P1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.3.4~6.P1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.3.4~6.P1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.3.4~6.P1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"caching-nameserver", rpm:"caching-nameserver~9.3.4~6.P1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
