###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mod_perl FEDORA-2007-576
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
tag_insight = "Mod_perl incorporates a Perl interpreter into the Apache web server,
  so that the Apache web server can directly execute Perl code.
  Mod_perl links the Perl runtime library into the Apache web server and
  provides an object-oriented Perl interface for Apache's C language
  API.  The end result is a quicker CGI script turnaround process, since
  no external Perl interpreter has to be started.

  Install mod_perl if you're installing the Apache web server and you'd
  like for it to directly incorporate a Perl interpreter.";

tag_affected = "mod_perl on Fedora Core 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-June/msg00152.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307246");
  script_version("$Revision: 6622 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 07:52:50 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:31:39 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2007-576");
  script_cve_id("CVE-2007-1349");
  script_name( "Fedora Update for mod_perl FEDORA-2007-576");

  script_tag(name:"summary", value:"Check for the Version of mod_perl");
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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"mod_perl", rpm:"mod_perl~2.0.2~5.2.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mod_perl-devel", rpm:"x86_64/mod_perl-devel~2.0.2~5.2.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mod_perl", rpm:"x86_64/mod_perl~2.0.2~5.2.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/mod_perl-debuginfo", rpm:"x86_64/debug/mod_perl-debuginfo~2.0.2~5.2.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mod_perl-devel", rpm:"i386/mod_perl-devel~2.0.2~5.2.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/mod_perl-debuginfo", rpm:"i386/debug/mod_perl-debuginfo~2.0.2~5.2.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mod_perl", rpm:"i386/mod_perl~2.0.2~5.2.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
