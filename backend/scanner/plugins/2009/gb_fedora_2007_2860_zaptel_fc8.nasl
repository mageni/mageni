###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for zaptel FEDORA-2007-2860
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
tag_affected = "zaptel on Fedora 8";
tag_insight = "Tools and libraries for using/configuring/monitoring Zapata telephony
  interfaces.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-November/msg00616.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306136");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:01:32 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2007-2860");
  script_cve_id("CVE-2007-5690");
  script_name( "Fedora Update for zaptel FEDORA-2007-2860");

  script_tag(name:"summary", value:"Check for the Version of zaptel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "FC8")
{

  if ((res = isrpmvuln(pkg:"zaptel", rpm:"zaptel~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel", rpm:"zaptel~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-devel", rpm:"zaptel-devel~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-utils", rpm:"zaptel-utils~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-lib", rpm:"zaptel-lib~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-debuginfo", rpm:"zaptel-debuginfo~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-lib", rpm:"zaptel-lib~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-utils", rpm:"zaptel-utils~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-debuginfo", rpm:"zaptel-debuginfo~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-devel", rpm:"zaptel-devel~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel", rpm:"zaptel~1.4.6~1.fc8", rls:"FC8")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}