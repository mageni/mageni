###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for wireshark RHSA-2013:0125-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00008.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870879");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:41:44 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2175", "CVE-2011-2698",
                "CVE-2011-4102", "CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0066",
                "CVE-2012-0067", "CVE-2012-4285", "CVE-2012-4289", "CVE-2012-4290",
                "CVE-2012-4291");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for wireshark RHSA-2013:0125-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"wireshark on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Wireshark, previously known as Ethereal, is a network protocol analyzer. It
  is used to capture and browse the traffic running on a computer network.

  A heap-based buffer overflow flaw was found in the way Wireshark handled
  Endace ERF (Extensible Record Format) capture files. If Wireshark opened a
  specially-crafted ERF capture file, it could crash or, possibly, execute
  arbitrary code as the user running Wireshark. (CVE-2011-4102)

  Several denial of service flaws were found in Wireshark. Wireshark could
  crash or stop responding if it read a malformed packet off a network, or
  opened a malicious dump file. (CVE-2011-1958, CVE-2011-1959, CVE-2011-2175,
  CVE-2011-2698, CVE-2012-0041, CVE-2012-0042, CVE-2012-0066, CVE-2012-0067,
  CVE-2012-4285, CVE-2012-4289, CVE-2012-4290, CVE-2012-4291)

  The CVE-2011-1958, CVE-2011-1959, CVE-2011-2175, and CVE-2011-4102 issues
  were discovered by Huzaifa Sidhpurwala of the Red Hat Security Response
  Team.

  This update also fixes the following bugs:

  * When Wireshark starts with the X11 protocol being tunneled through an SSH
  connection, it automatically prepares its capture filter to omit the SSH
  packets. If the SSH connection was to a link-local IPv6 address including
  an interface name (for example ssh -X [ipv6addr]%eth0), Wireshark parsed
  this address erroneously, constructed an incorrect capture filter and
  refused to capture packets. The 'Invalid capture filter' message was
  displayed. With this update, parsing of link-local IPv6 addresses is fixed
  and Wireshark correctly prepares a capture filter to omit SSH packets over
  a link-local IPv6 connection. (BZ#438473)

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.15~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~1.0.15~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.0.15~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
