###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openssh RHSA-2008:0855-01
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
tag_insight = "OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation.

  Last week Red Hat detected an intrusion on certain of its computer systems
  and took immediate action. While the investigation into the intrusion is
  on-going, our initial focus  was to review and test the distribution
  channel we use with our customers, Red Hat Network (RHN) and its associated
  security measures. Based on these efforts, we remain highly confident that
  our systems and processes prevented the intrusion from compromising RHN or
  the content distributed via RHN and accordingly believe that customers who
  keep their systems updated using Red Hat Network are not at risk.  We are
  issuing this alert primarily for those who may obtain Red Hat binary
  packages via channels other than those of official Red Hat subscribers.
  
  In connection with the incident, the intruder was able to sign a small
  number of OpenSSH packages relating only to Red Hat Enterprise Linux 4
  (i386 and x86_64 architectures only) and Red Hat Enterprise Linux 5 (x86_64
  architecture only).  As a precautionary measure, we are releasing an
  updated version of these packages, and have published a list of the
  tampered packages and how to detect them at
  <a  rel= &qt nofollow &qt  href= &qt http://www.redhat.com/security/data/openssh-blacklist.html &qt >http://www.redhat.com/security/data/openssh-blacklist.html</a>
  
  To reiterate, our processes and efforts to date indicate that packages
  obtained by Red Hat Enterprise Linux subscribers via Red Hat Network are
  not at risk.
  
  These packages also fix a low severity flaw in the way ssh handles X11
  cookies when creating X11 forwarding connections.  When ssh was unable to
  create untrusted cookie, ssh used a trusted cookie instead, possibly
  allowing the administrative user of a untrusted remote server, or untrusted
  application run on the remote server, to gain unintended access to a users
  local X server. (CVE-2007-4752)";

tag_affected = "openssh on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4,
  Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-August/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306982");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2008:0855-01");
  script_cve_id("CVE-2007-4752");
  script_name( "RedHat Update for openssh RHSA-2008:0855-01");

  script_tag(name:"summary", value:"Check for the Version of openssh");
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

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~4.3p2~26.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~4.3p2~26.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~4.3p2~26.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~4.3p2~26.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~4.3p2~26.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~3.9p1~11.el4_7", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~3.9p1~11.el4_7", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~3.9p1~11.el4_7", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~3.9p1~11.el4_7", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~3.9p1~11.el4_7", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~3.9p1~11.el4_7", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
