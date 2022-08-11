###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for trousers RHSA-2014:1507-02
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
  script_oid("1.3.6.1.4.1.25623.1.0.871269");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-10-15 06:07:55 +0200 (Wed, 15 Oct 2014)");
  script_cve_id("CVE-2012-0698");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for trousers RHSA-2014:1507-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'trousers'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"TrouSerS is an implementation of the Trusted Computing Group's Software
Stack (TSS) specification. You can use TrouSerS to write applications that
make use of your TPM hardware. TPM hardware can create, store and use RSA
keys securely (without ever being exposed in memory), verify a platform's
software state using cryptographic hashes and more.

A flaw was found in the way tcsd, the daemon that manages Trusted Computing
resources, processed incoming TCP packets. A remote attacker could send a
specially crafted TCP packet that, when processed by tcsd, could cause the
daemon to crash. Note that by default tcsd accepts requests on localhost
only. (CVE-2012-0698)

Red Hat would like to thank Andrew Lutomirski for reporting this issue.

The trousers package has been upgraded to upstream version 0.3.13, which
provides a number of bug fixes and enhancements over the previous version,
including corrected internal symbol names to avoid collisions with other
applications, fixed memory leaks, added IPv6 support, fixed buffer handling
in tcsd, as well as changed the license to BSD. (BZ#633584, BZ#1074634)

All trousers users are advised to upgrade to these updated packages, which
correct these issues and add these enhancements.");
  script_tag(name:"affected", value:"trousers on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-October/msg00019.html");
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

  if ((res = isrpmvuln(pkg:"trousers", rpm:"trousers~0.3.13~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"trousers-debuginfo", rpm:"trousers-debuginfo~0.3.13~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
