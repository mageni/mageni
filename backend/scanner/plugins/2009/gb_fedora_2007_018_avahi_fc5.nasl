###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for avahi FEDORA-2007-018
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
tag_affected = "avahi on Fedora Core 5";
tag_insight = "Avahi is a system which facilitates service discovery on
  a local network -- this means that you can plug your laptop or
  computer into a network and instantly be able to view other people who
  you can chat with, find printers to print to or find files being
  shared. This kind of technology is already found in MacOS X (branded
  'Rendezvous', 'Bonjour' and sometimes 'ZeroConf') and is very
  convenient.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-January/msg00035.html");
  script_oid("1.3.6.1.4.1.25623.1.0.310553");
  script_version("$Revision: 6622 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 07:52:50 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:31:39 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2007-018");
  script_cve_id("CVE-2006-6870", "CVE-2006-5461");
  script_name( "Fedora Update for avahi FEDORA-2007-018");

  script_tag(name:"summary", value:"Check for the Version of avahi");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms");
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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/avahi-debuginfo", rpm:"x86_64/debug/avahi-debuginfo~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-compat-howl", rpm:"x86_64/avahi-compat-howl~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-compat-libdns_sd-devel", rpm:"x86_64/avahi-compat-libdns_sd-devel~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-tools", rpm:"x86_64/avahi-tools~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-glib", rpm:"x86_64/avahi-glib~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi", rpm:"x86_64/avahi~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-qt3", rpm:"x86_64/avahi-qt3~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-qt3-devel", rpm:"x86_64/avahi-qt3-devel~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-devel", rpm:"x86_64/avahi-devel~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-compat-libdns_sd", rpm:"x86_64/avahi-compat-libdns_sd~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-sharp", rpm:"x86_64/avahi-sharp~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-compat-howl-devel", rpm:"x86_64/avahi-compat-howl-devel~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/avahi-glib-devel", rpm:"x86_64/avahi-glib-devel~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-sharp", rpm:"i386/avahi-sharp~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-compat-howl", rpm:"i386/avahi-compat-howl~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-compat-howl-devel", rpm:"i386/avahi-compat-howl-devel~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-glib-devel", rpm:"i386/avahi-glib-devel~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-tools", rpm:"i386/avahi-tools~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi", rpm:"i386/avahi~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-glib", rpm:"i386/avahi-glib~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-devel", rpm:"i386/avahi-devel~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-qt3", rpm:"i386/avahi-qt3~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-compat-libdns_sd", rpm:"i386/avahi-compat-libdns_sd~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-qt3-devel", rpm:"i386/avahi-qt3-devel~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/avahi-compat-libdns_sd-devel", rpm:"i386/avahi-compat-libdns_sd-devel~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/avahi-debuginfo", rpm:"i386/debug/avahi-debuginfo~0.6.11~3.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}