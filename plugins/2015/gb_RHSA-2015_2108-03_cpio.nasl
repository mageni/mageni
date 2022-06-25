###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for cpio RHSA-2015:2108-03
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
  script_oid("1.3.6.1.4.1.25623.1.0.871486");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:20:39 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2014-9112");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for cpio RHSA-2015:2108-03");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'cpio'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The cpio packages provide the GNU cpio
utility for creating and extracting archives, or copying files from one place
to another.

A heap-based buffer overflow flaw was found in cpio's list_file() function.
An attacker could provide a specially crafted archive that, when processed
by cpio, would crash cpio, or potentially lead to arbitrary code execution.
(CVE-2014-9112)

This update fixes the following bugs:

  * Previously, during archive creation, cpio internals did not detect a
read() system call failure. Based on the premise that the call succeeded,
cpio terminated unexpectedly with a segmentation fault without processing
further files. The underlying source code has been patched, and an archive
is now created successfully. (BZ#1138148)

  * Previously, running the cpio command without parameters on Red Hat
Enterprise Linux 7 with Russian as the default language resulted in an
error message that was not accurate in Russian due to an error in spelling.
This has been corrected and the Russian error message is spelled correctly.
(BZ#1075513)

All cpio users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"cpio on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00020.html");
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

  if ((res = isrpmvuln(pkg:"cpio", rpm:"cpio~2.11~24.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cpio-debuginfo", rpm:"cpio-debuginfo~2.11~24.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
