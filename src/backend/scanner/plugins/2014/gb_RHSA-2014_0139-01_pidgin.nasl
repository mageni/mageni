###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for pidgin RHSA-2014:0139-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871123");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-02-11 10:51:04 +0530 (Tue, 11 Feb 2014)");
  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479",
                "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484",
                "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490",
                "CVE-2014-0020");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for pidgin RHSA-2014:0139-01");


  script_tag(name:"affected", value:"pidgin on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A heap-based buffer overflow flaw was found in the way Pidgin processed
certain HTTP responses. A malicious server could send a specially crafted
HTTP response, causing Pidgin to crash or potentially execute arbitrary
code with the permissions of the user running Pidgin. (CVE-2013-6485)

Multiple heap-based buffer overflow flaws were found in several protocol
plug-ins in Pidgin (Gadu-Gadu, MXit, SIMPLE). A malicious server could send
a specially crafted message, causing Pidgin to crash or potentially execute
arbitrary code with the permissions of the user running Pidgin.
(CVE-2013-6487, CVE-2013-6489, CVE-2013-6490)

Multiple denial of service flaws were found in several protocol plug-ins in
Pidgin (Yahoo!, XMPP, MSN, stun, IRC). A remote attacker could use these
flaws to crash Pidgin by sending a specially crafted message.
(CVE-2012-6152, CVE-2013-6477, CVE-2013-6481, CVE-2013-6482, CVE-2013-6484,
CVE-2014-0020)

It was found that the Pidgin XMPP protocol plug-in did not verify the
origin of 'iq' replies. A remote attacker could use this flaw to spoof an
'iq' reply, which could lead to injection of fake data or cause Pidgin to
crash via a NULL pointer dereference. (CVE-2013-6483)

A flaw was found in the way Pidgin parsed certain HTTP response headers.
A remote attacker could use this flaw to crash Pidgin via a specially
crafted HTTP response header. (CVE-2013-6479)

It was found that Pidgin crashed when a mouse pointer was hovered over a
long URL. A remote attacker could use this flaw to crash Pidgin by sending
a message containing a long URL string. (CVE-2013-6478)

Red Hat would like to thank the Pidgin project for reporting these issues.
Upstream acknowledges Thijs Alkemade, Robert Vehse, Jaime Breva Ribes,
Jacob Appelbaum of the Tor Project, Daniel Atallah, Fabian Yamaguchi and
Christian Wressnegger of the University of Goettingen, Matt Jones of
Volvent, and Yves Younan, Ryan Pentney, and Pawel Janic of Sourcefire VRT
as the original reporters of these issues.

All pidgin users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. Pidgin must be
restarted for this update to take effect.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-February/msg00009.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.7.9~27.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.7.9~27.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-debuginfo", rpm:"pidgin-debuginfo~2.7.9~27.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
