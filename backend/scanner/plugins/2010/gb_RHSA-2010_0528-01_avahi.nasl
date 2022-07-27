###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for avahi RHSA-2010:0528-01
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
tag_insight = "Avahi is an implementation of the DNS Service Discovery and Multicast DNS
  specifications for Zero Configuration Networking. It facilitates service
  discovery on a local network. Avahi and Avahi-aware applications allow you
  to plug your computer into a network and, with no configuration, view other
  people to chat with, view printers to print to, and find shared files on
  other computers.

  A flaw was found in the way the Avahi daemon (avahi-daemon) processed
  Multicast DNS (mDNS) packets with corrupted checksums. An attacker on the
  local network could use this flaw to cause avahi-daemon on a target system
  to exit unexpectedly via specially-crafted mDNS packets. (CVE-2010-2244)
  
  A flaw was found in the way avahi-daemon processed incoming unicast mDNS
  messages. If the mDNS reflector were enabled on a system, an attacker on
  the local network could send a specially-crafted unicast mDNS message to
  that system, resulting in its avahi-daemon flooding the network with a
  multicast packet storm, and consuming a large amount of CPU. Note: The mDNS
  reflector is disabled by default. (CVE-2009-0758)
  
  All users are advised to upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the update,
  avahi-daemon will be restarted automatically.";

tag_affected = "avahi on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-July/msg00006.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313206");
  script_version("$Revision: 8287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-16 10:40:49 +0200 (Fri, 16 Jul 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "RHSA", value: "2010:0528-01");
  script_cve_id("CVE-2009-0758", "CVE-2010-2244");
  script_name("RedHat Update for avahi RHSA-2010:0528-01");

  script_tag(name: "summary" , value: "Check for the Version of avahi");
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

  if ((res = isrpmvuln(pkg:"avahi", rpm:"avahi~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-compat-howl", rpm:"avahi-compat-howl~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-compat-howl-devel", rpm:"avahi-compat-howl-devel~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-compat-libdns_sd", rpm:"avahi-compat-libdns_sd~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-compat-libdns_sd-devel", rpm:"avahi-compat-libdns_sd-devel~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-debuginfo", rpm:"avahi-debuginfo~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-devel", rpm:"avahi-devel~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-glib", rpm:"avahi-glib~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-glib-devel", rpm:"avahi-glib-devel~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-qt3", rpm:"avahi-qt3~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-qt3-devel", rpm:"avahi-qt3-devel~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"avahi-tools", rpm:"avahi-tools~0.6.16~9.el5_5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
