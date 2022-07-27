###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for python RHSA-2011:0027-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-January/msg00008.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870377");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-01-14 16:07:43 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5983", "CVE-2009-4134", "CVE-2010-1449", "CVE-2010-1450", "CVE-2010-1634", "CVE-2010-2089");
  script_name("RedHat Update for python RHSA-2011:0027-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"python on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Python is an interpreted, interactive, object-oriented programming
  language.

  It was found that many applications embedding the Python interpreter did
  not specify a valid full path to the script or application when calling the
  PySys_SetArgv API function, which could result in the addition of the
  current working directory to the module search path (sys.path). A local
  attacker able to trick a victim into running such an application in an
  attacker-controlled directory could use this flaw to execute code with the
  victim's privileges. This update adds the PySys_SetArgvEx API. Developers
  can modify their applications to use this new API, which sets sys.argv
  without modifying sys.path. (CVE-2008-5983)

  Multiple flaws were found in the Python rgbimg module. If an application
  written in Python was using the rgbimg module and loaded a
  specially-crafted SGI image file, it could cause the application to crash
  or, possibly, execute arbitrary code with the privileges of the user
  running the application. (CVE-2009-4134, CVE-2010-1449, CVE-2010-1450)

  Multiple flaws were found in the Python audioop module. Supplying certain
  inputs could cause the audioop module to crash or, possibly, execute
  arbitrary code. (CVE-2010-1634, CVE-2010-2089)

  This update also fixes the following bugs:

  * When starting a child process from the subprocess module in Python 2.4,
  the parent process could leak file descriptors if an error occurred. This
  update resolves the issue. (BZ#609017)

  * Prior to Python 2.7, programs that used 'ulimit -n' to enable
  communication with large numbers of subprocesses could still monitor only
  1024 file descriptors at a time, which caused an exception:

    ValueError: filedescriptor out of range in select()

  This was due to the subprocess module using the 'select' system call. The
  module now uses the 'poll' system call, removing this limitation.
  (BZ#609020)

  * Prior to Python 2.5, the tarfile module failed to unpack tar files if the
  path was longer than 100 characters. This update backports the tarfile
  module from Python 2.5 and the issue no longer occurs. (BZ#263401)

  * The email module incorrectly implemented the logic for obtaining
  attachment file names: the get_filename() fallback for using the deprecated
  'name' parameter of the 'Content-Type' header erroneously used the
  'Content-Disposition' header. This update backports a fix from Python 2.6,
  which resolves this issue. (BZ#644147)

  * Prior to version 2.5, Python's ...

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

  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.4.3~43.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.4.3~43.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.4.3~43.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.4.3~43.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.4.3~43.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.4.3~43.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
