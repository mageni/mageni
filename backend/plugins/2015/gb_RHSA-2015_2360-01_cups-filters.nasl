###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for cups-filters RHSA-2015:2360-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871485");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:20:12 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-3258", "CVE-2015-3279");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for cups-filters RHSA-2015:2360-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups-filters'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The cups-filters packages contain back ends,
filters, and other software that was once part of the core Common UNIX Printing
System (CUPS) distribution but is now maintained independently.

A heap-based buffer overflow flaw and an integer overflow flaw leading to a
heap-based buffer overflow were discovered in the way the texttopdf utility
of cups-filter processed print jobs with a specially crafted line size.
An attacker able to submit print jobs could use these flaws to crash
texttopdf or, possibly, execute arbitrary code with the privileges of the
'lp' user. (CVE-2015-3258, CVE-2015-3279)

The CVE-2015-3258 issue was discovered by Petr Sklenar of Red Hat.

Notably, this update also fixes the following bug:

  * Previously, when polling CUPS printers from a CUPS server, when a printer
name contained an underscore (_), the client displayed the name containing
a hyphen (-) instead. This made the print queue unavailable. With this
update, CUPS allows the underscore character in printer names, and printers
appear as shown on the CUPS server as expected. (BZ#1167408)

In addition, this update adds the following enhancement:

  * Now, the information from local and remote CUPS servers is cached during
each poll, and the CUPS server load is reduced. (BZ#1191691)

All cups-filters users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement.");
  script_tag(name:"affected", value:"cups-filters on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00041.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"cups-filters", rpm:"cups-filters~1.0.35~21.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-filters-debuginfo", rpm:"cups-filters-debuginfo~1.0.35~21.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-filters-libs", rpm:"cups-filters-libs~1.0.35~21.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
