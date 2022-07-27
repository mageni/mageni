###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for bind RHSA-2010:0062-02
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
tag_insight = "The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
  Name System (DNS) protocols. BIND includes a DNS server (named); a resolver
  library (routines for applications to use when interfacing with DNS); and
  tools for verifying that the DNS server is operating correctly.

  A flaw was found in the BIND DNSSEC NSEC/NSEC3 validation code. If BIND was
  running as a DNSSEC-validating resolver, it could incorrectly cache
  NXDOMAIN responses, as if they were valid, for records proven by NSEC or
  NSEC3 to exist. A remote attacker could use this flaw to cause a BIND
  server to return the bogus, cached NXDOMAIN responses for valid records and
  prevent users from retrieving those records (denial of service).
  (CVE-2010-0097)
  
  The original fix for CVE-2009-4022 was found to be incomplete. BIND was
  incorrectly caching certain responses without performing proper DNSSEC
  validation. CNAME and DNAME records could be cached, without proper DNSSEC
  validation, when received from processing recursive client queries that
  requested DNSSEC records but indicated that checking should be disabled. A
  remote attacker could use this flaw to bypass the DNSSEC validation check
  and perform a cache poisoning attack if the target BIND server was
  receiving such client queries. (CVE-2010-0290)
  
  All BIND users are advised to upgrade to these updated packages, which
  contain a backported patch to resolve these issues. After installing the
  update, the BIND daemon (named) will be restarted automatically.";

tag_affected = "bind on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-January/msg00018.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313489");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-25 13:25:54 +0100 (Mon, 25 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "RHSA", value: "2010:0062-02");
  script_cve_id("CVE-2010-0097", "CVE-2010-0290", "CVE-2009-4022");
  script_name("RedHat Update for bind RHSA-2010:0062-02");

  script_tag(name: "summary" , value: "Check for the Version of bind");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.3.6~4.P1.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.3.6~4.P1.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.3.6~4.P1.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.3.6~4.P1.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libbind-devel", rpm:"bind-libbind-devel~9.3.6~4.P1.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.3.6~4.P1.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.3.6~4.P1.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.3.6~4.P1.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"caching-nameserver", rpm:"caching-nameserver~9.3.6~4.P1.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
