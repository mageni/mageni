###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gimp RHSA-2012:1181-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-August/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870809");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-08-21 11:43:14 +0530 (Tue, 21 Aug 2012)");
  script_cve_id("CVE-2009-3909", "CVE-2011-2896", "CVE-2012-3402", "CVE-2012-3403", "CVE-2012-3481");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for gimp RHSA-2012:1181-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"gimp on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The GIMP (GNU Image Manipulation Program) is an image composition and
  editing program.

  Multiple integer overflow flaws, leading to heap-based buffer overflows,
  were found in the GIMP's Adobe Photoshop (PSD) image file plug-in. An
  attacker could create a specially-crafted PSD image file that, when opened,
  could cause the PSD plug-in to crash or, potentially, execute arbitrary
  code with the privileges of the user running the GIMP. (CVE-2009-3909,
  CVE-2012-3402)

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the GIMP's GIF image format plug-in. An attacker could create a
  specially-crafted GIF image file that, when opened, could cause the GIF
  plug-in to crash or, potentially, execute arbitrary code with the
  privileges of the user running the GIMP. (CVE-2012-3481)

  A heap-based buffer overflow flaw was found in the GIMP's KiSS CEL file
  format plug-in. An attacker could create a specially-crafted KiSS palette
  file that, when opened, could cause the CEL plug-in to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the GIMP. (CVE-2012-3403)

  Red Hat would like to thank Secunia Research for reporting CVE-2009-3909,
  and Matthias Weckbecker of the SUSE Security Team for reporting
  CVE-2012-3481.

  Users of the GIMP are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. The GIMP must be
  restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.2.13~2.0.7.el5_8.5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-debuginfo", rpm:"gimp-debuginfo~2.2.13~2.0.7.el5_8.5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.2.13~2.0.7.el5_8.5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-libs", rpm:"gimp-libs~2.2.13~2.0.7.el5_8.5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
