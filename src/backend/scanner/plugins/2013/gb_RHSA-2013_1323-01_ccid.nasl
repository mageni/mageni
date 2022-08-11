###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ccid RHSA-2013:1323-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871045");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-10-03 10:17:15 +0530 (Thu, 03 Oct 2013)");
  script_cve_id("CVE-2010-4530");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for ccid RHSA-2013:1323-01");


  script_tag(name:"affected", value:"ccid on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"insight", value:"Chip/Smart Card Interface Devices (CCID) is a USB smart card reader
standard followed by most modern smart card readers. The ccid package
provides a Generic, USB-based CCID driver for readers, which follow this
standard.

An integer overflow, leading to an array index error, was found in the way
the CCID driver processed a smart card's serial number. A local attacker
could use this flaw to execute arbitrary code with the privileges of the
user running the PC/SC Lite pcscd daemon (root, by default), by inserting a
specially-crafted smart card. (CVE-2010-4530)

This update also fixes the following bug:

  * The pcscd service failed to read from the SafeNet Smart Card 650 v1 when
it was inserted into a smart card reader. The operation failed with a
'IFDHPowerICC() PowerUp failed' error message. This was due to the card
taking a long time to respond with a full Answer To Reset (ATR) request,
which lead to a timeout, causing the card to fail to power up. This update
increases the timeout value so that the aforementioned request is processed
properly, and the card is powered on as expected. (BZ#907821)

All ccid users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-September/msg00053.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ccid'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"ccid", rpm:"ccid~1.3.8~2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ccid-debuginfo", rpm:"ccid-debuginfo~1.3.8~2.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
