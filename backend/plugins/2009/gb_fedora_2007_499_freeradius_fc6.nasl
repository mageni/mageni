###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for freeradius FEDORA-2007-499
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
tag_insight = "The FreeRADIUS Server Project is a high performance and highly configurable
  GPL'd free RADIUS server. The server is similar in some respects to
  Livingston's 2.0 server.  While FreeRADIUS started as a variant of the
  Cistron RADIUS server, they don't share a lot in common any more. It now has
  many more features than Cistron or Livingston, and is much more configurable.

  FreeRADIUS is an Internet authentication daemon, which implements the RADIUS
  protocol, as defined in RFC 2865 (and others). It allows Network Access
  Servers (NAS boxes) to perform authentication for dial-up users. There are
  also RADIUS clients available for Web servers, firewalls, Unix logins, and
  more.  Using RADIUS allows authentication and authorization for a network to
  be centralized, and minimizes the amount of re-configuration which has to be
  done when adding or deleting new users";

tag_affected = "freeradius on Fedora Core 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-May/msg00019.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307641");
  script_version("$Revision: 6622 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 07:52:50 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:27:46 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2007-499");
  script_cve_id("CVE-2007-2028");
  script_name( "Fedora Update for freeradius FEDORA-2007-499");

  script_tag(name:"summary", value:"Check for the Version of freeradius");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms");
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

if(release == "FC6")
{

  if ((res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/freeradius-postgresql", rpm:"x86_64/freeradius-postgresql~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/freeradius-debuginfo", rpm:"x86_64/debug/freeradius-debuginfo~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/freeradius", rpm:"x86_64/freeradius~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/freeradius-unixODBC", rpm:"x86_64/freeradius-unixODBC~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/freeradius-mysql", rpm:"x86_64/freeradius-mysql~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/freeradius", rpm:"i386/freeradius~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/freeradius-debuginfo", rpm:"i386/debug/freeradius-debuginfo~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/freeradius-mysql", rpm:"i386/freeradius-mysql~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/freeradius-postgresql", rpm:"i386/freeradius-postgresql~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/freeradius-unixODBC", rpm:"i386/freeradius-unixODBC~1.1.3~2.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
