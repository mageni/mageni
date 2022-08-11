###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for samba RHSA-2008:0290-01
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
tag_insight = "Samba is a suite of programs used by machines to share files, printers, and
  other information.

  A heap-based buffer overflow flaw was found in the way Samba clients handle
  over-sized packets. If a client connected to a malicious Samba server, it
  was possible to execute arbitrary code as the Samba client user. It was
  also possible for a remote user to send a specially crafted print request
  to a Samba server that could result in the server executing the vulnerable
  client code, resulting in arbitrary code execution with the permissions of
  the Samba server. (CVE-2008-1105)
  
  Red Hat would like to thank Alin Rad Pop of Secunia Research for
  responsibly disclosing this issue.
  
  This update also addresses two issues which prevented Samba from joining
  certain Windows domains with tightened security policies, and prevented
  certain signed SMB content from working as expected:
  
  * when some Windows® 2000-based domain controllers were set to use
  mandatory signing, Samba clients would drop the connection because of an
  error when generating signatures. This presented as a &quot;Server packet had
  invalid SMB signature&quot; error to the Samba client. This update corrects the
  signature generation error.
  
  * Samba servers using the &quot;net ads join&quot; command to connect to a Windows
  Server® 2003-based domain would fail with &quot;failed to get schannel session
  key from server&quot; and &quot;NT_STATUS_ACCESS_DENIED&quot; errors. This update
  correctly binds to the NETLOGON share, allowing Samba servers to connect to
  the domain properly.
  
  Users of Samba are advised to upgrade to these updated packages, which
  contain a backported patch to resolve these issues.";

tag_affected = "samba on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-May/msg00026.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307370");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2008:0290-01");
  script_cve_id("CVE-2008-1105");
  script_name( "RedHat Update for samba RHSA-2008:0290-01");

  script_tag(name:"summary", value:"Check for the Version of samba");
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

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.28~1.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.28~1.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.28~1.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~3.0.28~1.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.28~1.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
