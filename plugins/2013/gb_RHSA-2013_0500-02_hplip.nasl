###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for hplip RHSA-2013:0500-02
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00044.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870929");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-02-22 10:02:06 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2011-2722", "CVE-2013-0200");
  script_bugtraq_id(48892, 58079);
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_name("RedHat Update for hplip RHSA-2013:0500-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hplip'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"hplip on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The hplip packages contain the Hewlett-Packard Linux Imaging and Printing
  Project (HPLIP), which provides drivers for Hewlett-Packard printers and
  multi-function peripherals.

  Several temporary file handling flaws were found in HPLIP. A local attacker
  could use these flaws to perform a symbolic link attack, overwriting
  arbitrary files accessible to a process using HPLIP. (CVE-2013-0200,
  CVE-2011-2722)

  The CVE-2013-0200 issues were discovered by Tim Waugh of Red Hat.

  The hplip packages have been upgraded to upstream version 3.12.4, which
  provides a number of bug fixes and enhancements over the previous version.
  (BZ#731900)

  This update also fixes the following bugs:

  * Previously, the hpijs package required the obsolete cupsddk-drivers
  package, which was provided by the cups package. Under certain
  circumstances, this dependency caused hpijs installation to fail. This
  bug has been fixed and hpijs no longer requires cupsddk-drivers.
  (BZ#829453)

  * The configuration of the Scanner Access Now Easy (SANE) back end is
  located in the /etc/sane.d/dll.d/ directory, however, the hp-check
  utility checked only the /etc/sane.d/dll.conf file. Consequently,
  hp-check checked for correct installation, but incorrectly reported a
  problem with the way the SANE back end was installed. With this update,
  hp-check properly checks for installation problems in both locations as
  expected. (BZ#683007)

  All users of hplip are advised to upgrade to these updated packages, which
  fix these issues and add these enhancements.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"hpijs", rpm:"hpijs~3.12.4~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.12.4~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-common", rpm:"hplip-common~3.12.4~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-debuginfo", rpm:"hplip-debuginfo~3.12.4~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-gui", rpm:"hplip-gui~3.12.4~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-libs", rpm:"hplip-libs~3.12.4~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsane-hpaio", rpm:"libsane-hpaio~3.12.4~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
