###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for X11 client libraries RHSA-2014:1436-02
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
  script_oid("1.3.6.1.4.1.25623.1.0.871265");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-10-15 06:05:51 +0200 (Wed, 15 Oct 2014)");
  script_cve_id("CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984",
                "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1987", "CVE-2013-1988",
                "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1995",
                "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000",
                "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004",
                "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2064", "CVE-2013-2066");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for X11 client libraries RHSA-2014:1436-02");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'X11 client libraries'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The X11 (Xorg) libraries provide library routines that are used within all
X Window applications.

Multiple integer overflow flaws, leading to heap-based buffer overflows,
were found in the way various X11 client libraries handled certain protocol
data. An attacker able to submit invalid protocol data to an X11 server via
a malicious X11 client could use either of these flaws to potentially
escalate their privileges on the system. (CVE-2013-1981, CVE-2013-1982,
CVE-2013-1983, CVE-2013-1984, CVE-2013-1985, CVE-2013-1986, CVE-2013-1987,
CVE-2013-1988, CVE-2013-1989, CVE-2013-1990, CVE-2013-1991, CVE-2013-2003,
CVE-2013-2062, CVE-2013-2064)

Multiple array index errors, leading to heap-based buffer out-of-bounds
write flaws, were found in the way various X11 client libraries handled
data returned from an X11 server. A malicious X11 server could possibly use
this flaw to execute arbitrary code with the privileges of the user running
an X11 client. (CVE-2013-1997, CVE-2013-1998, CVE-2013-1999, CVE-2013-2000,
CVE-2013-2001, CVE-2013-2002, CVE-2013-2066)

A buffer overflow flaw was found in the way the XListInputDevices()
function of X.Org X11's libXi runtime library handled signed numbers.
A malicious X11 server could possibly use this flaw to execute arbitrary
code with the privileges of the user running an X11 client. (CVE-2013-1995)

A flaw was found in the way the X.Org X11 libXt runtime library used
uninitialized pointers. A malicious X11 server could possibly use this flaw
to execute arbitrary code with the privileges of the user running an X11
client. (CVE-2013-2005)

Two stack-based buffer overflow flaws were found in the way libX11, the
Core X11 protocol client library, processed certain user-specified files.
A malicious X11 server could possibly use this flaw to crash an X11 client
via a specially crafted file. (CVE-2013-2004)

The xkeyboard-config package has been upgraded to upstream version 2.11,
which provides a number of bug fixes and enhancements over the previous
version. (BZ#1077471)

This update also fixes the following bugs:

  * Previously, updating the mesa-libGL package did not update the libX11
package, although it was listed as a dependency of mesa-libGL. This bug has
been fixed and updating mesa-libGL now updates all dependent packages as
expected. (BZ#1054614)

  * Previously, closing a customer application could occasionally cause the X
Server to terminate unexpectedly. After this update, the X Server no longer
hangs when a user closes a customer application. (BZ#971626)

All X11 client libraries users are advised to upgrade to these updated
packages, which correct these issues and add these enhancements.");
  script_tag(name:"affected", value:"X11 client libraries on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-October/msg00018.html");
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

  if ((res = isrpmvuln(pkg:"libX11", rpm:"libX11~1.6.0~2.2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libX11-debuginfo", rpm:"libX11-debuginfo~1.6.0~2.2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.0~2.2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXcursor", rpm:"libXcursor~1.1.14~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXcursor-debuginfo", rpm:"libXcursor-debuginfo~1.1.14~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXcursor-devel", rpm:"libXcursor-devel~1.1.14~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXext", rpm:"libXext~1.3.2~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXext-debuginfo", rpm:"libXext-debuginfo~1.3.2~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXext-devel", rpm:"libXext-devel~1.3.2~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfixes", rpm:"libXfixes~5.0.1~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfixes-debuginfo", rpm:"libXfixes-debuginfo~5.0.1~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfixes-devel", rpm:"libXfixes-devel~5.0.1~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXi", rpm:"libXi~1.7.2~2.2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXi-debuginfo", rpm:"libXi-debuginfo~1.7.2~2.2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXi-devel", rpm:"libXi-devel~1.7.2~2.2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXinerama", rpm:"libXinerama~1.1.3~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXinerama-debuginfo", rpm:"libXinerama-debuginfo~1.1.3~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXinerama-devel", rpm:"libXinerama-devel~1.1.3~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXp", rpm:"libXp~1.0.2~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXp-debuginfo", rpm:"libXp-debuginfo~1.0.2~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXp-devel", rpm:"libXp-devel~1.0.2~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrandr", rpm:"libXrandr~1.4.1~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrandr-debuginfo", rpm:"libXrandr-debuginfo~1.4.1~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrandr-devel", rpm:"libXrandr-devel~1.4.1~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrender", rpm:"libXrender~0.9.8~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrender-debuginfo", rpm:"libXrender-debuginfo~0.9.8~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXrender-devel", rpm:"libXrender-devel~0.9.8~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXres", rpm:"libXres~1.0.7~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXres-debuginfo", rpm:"libXres-debuginfo~1.0.7~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXt", rpm:"libXt~1.1.4~6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXt-debuginfo", rpm:"libXt-debuginfo~1.1.4~6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXt-devel", rpm:"libXt-devel~1.1.4~6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXtst", rpm:"libXtst~1.2.2~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXtst-debuginfo", rpm:"libXtst-debuginfo~1.2.2~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXtst-devel", rpm:"libXtst-devel~1.2.2~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXv", rpm:"libXv~1.0.9~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXv-debuginfo", rpm:"libXv-debuginfo~1.0.9~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXv-devel", rpm:"libXv-devel~1.0.9~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC", rpm:"libXvMC~1.0.8~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC-debuginfo", rpm:"libXvMC-debuginfo~1.0.8~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXxf86dga", rpm:"libXxf86dga~1.1.4~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXxf86dga-debuginfo", rpm:"libXxf86dga-debuginfo~1.1.4~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXxf86vm", rpm:"libXxf86vm~1.1.3~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXxf86vm-debuginfo", rpm:"libXxf86vm-debuginfo~1.1.3~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXxf86vm-devel", rpm:"libXxf86vm-devel~1.1.3~2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdmx", rpm:"libdmx~1.1.3~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdmx-debuginfo", rpm:"libdmx-debuginfo~1.1.3~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcb", rpm:"libxcb~1.9.1~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcb-debuginfo", rpm:"libxcb-debuginfo~1.9.1~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxcb-devel", rpm:"libxcb-devel~1.9.1~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libX11-common", rpm:"libX11-common~1.6.0~2.2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xkeyboard-config", rpm:"xkeyboard-config~2.11~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-proto-devel", rpm:"xorg-x11-proto-devel~7.7~9.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
