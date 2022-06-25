###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for snort FEDORA-2007-2060
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
tag_insight = "Snort is a libpcap-based packet sniffer/logger which
  can be used as a lightweight network intrusion detection system.
  It features rules based logging and can perform protocol analysis,
  content searching/matching and can be used to detect a variety of
  attacks and probes, such as buffer overflows, stealth port scans,
  CGI attacks, SMB probes, OS fingerprinting attempts, and much more.
  Snort has a real-time alerting capabilty, with alerts being sent to syslog,
  a separate &quot;alert&quot; file, or as a WinPopup message via Samba's smbclient

  Edit /etc/snort.conf to configure snort and use snort.d to start snort
  
  This rpm is different from previous rpms and while it will not clobber
  your current snortd file, you will need to modify it.
  
  There are 9 different packages available
  
  All of them require the base snort rpm.  Additionally, you will need
  to chose a binary to install.
  
  /usr/sbin/snort should end up being a symlink to a binary in one of
  the following configurations:
  
  plain      plain+flexresp
  mysql      mysql+flexresp
  postgresql postgresql+flexresp
  snmp       snmp+flexresp
  bloat      mysql+postgresql+flexresp+snmp
  
  Please see the documentation in /usr/share/doc/snort-2.7.0.1
  
  There are no rules in this package  the license  they are released under forbids
  us from repackaging them  and redistributing them.";

tag_affected = "snort on Fedora 7";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-September/msg00122.html");
  script_oid("1.3.6.1.4.1.25623.1.0.310105");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:01:32 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2007-2060");
  script_cve_id("CVE-2006-5276");
  script_name( "Fedora Update for snort FEDORA-2007-2060");

  script_tag(name:"summary", value:"Check for the Version of snort");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"snort", rpm:"snort~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-mysql+flexresp", rpm:"snort-mysql+flexresp~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-postgresql+flexresp", rpm:"snort-postgresql+flexresp~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-snmp+flexresp", rpm:"snort-snmp+flexresp~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-mysql", rpm:"snort-mysql~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-snmp", rpm:"snort-snmp~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-postgresql", rpm:"snort-postgresql~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort", rpm:"snort~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-debuginfo", rpm:"snort-debuginfo~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-plain+flexresp", rpm:"snort-plain+flexresp~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-bloat", rpm:"snort-bloat~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-snmp+flexresp", rpm:"snort-snmp+flexresp~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-snmp", rpm:"snort-snmp~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort", rpm:"snort~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-bloat", rpm:"snort-bloat~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-postgresql+flexresp", rpm:"snort-postgresql+flexresp~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-mysql+flexresp", rpm:"snort-mysql+flexresp~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-postgresql", rpm:"snort-postgresql~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-plain+flexresp", rpm:"snort-plain+flexresp~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-debuginfo", rpm:"snort-debuginfo~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snort-mysql", rpm:"snort-mysql~2.7.0.1~3.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
