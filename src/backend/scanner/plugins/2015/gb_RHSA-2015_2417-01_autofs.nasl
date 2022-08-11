###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for autofs RHSA-2015:2417-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871477");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:19:49 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2014-8169");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for autofs RHSA-2015:2417-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'autofs'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The autofs utility controls the operation
of the automount daemon. The daemon automatically mounts file systems when in
use and unmounts them when they are not busy.

It was found that program-based automounter maps that used interpreted
languages such as Python used standard environment variables to locate
and load modules of those languages. A local attacker could potentially use
this flaw to escalate their privileges on the system. (CVE-2014-8169)

Note: This issue has been fixed by adding the 'AUTOFS_' prefix to the
affected environment variables so that they are not used to subvert the
system. A configuration option ('force_standard_program_map_env') to
override this prefix and to use the environment variables without the
prefix has been added. In addition, warnings have been added to the manual
page and to the installed configuration file. Now, by default the standard
variables of the program map are provided only with the prefix added to
its name.

Red Hat would like to thank the Georgia Institute of Technology for
reporting this issue.

Notably, this update fixes the following bugs:

  * When the 'ls *' command was run in the root of an indirect mount, autofs
attempted to literally mount the wildcard character (*) causing it to be
added to the negative cache. If done before a valid mount, autofs then
failed on further mount attempts inside the mount point, valid or not. This
has been fixed, and wildcard map entries now function in the described
situation. (BZ#1166457)

  * When autofs encountered a syntax error consisting of a duplicate entry in
a multimap entry, it reported an error and did not mount the map entry.
With this update, autofs has been amended to report the problem in the log
to alert the system administrator and use the last seen instance of the
duplicate entry rather than fail. (BZ#1205600)

  * In the ldap and sss lookup modules, the map reading functions did not
distinguish between the 'no entry found' and 'service not available'
errors. Consequently, when the 'service not available' response was
returned from a master map read, autofs did not update the mounts.
An 'entry not found' return does not prevent the map update, so the ldap
and sss lookup modules were updated to distinguish between these two
returns and now work as expected. (BZ#1233065)

In addition, this update adds the following enhancement:

  * The description of the configuration parameter map_hash_table_size was
missing from the autofs.conf(5) man page and its description in the
configuration file comments was insufficient. A description of the
parameter has been added to autofs.conf ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"autofs on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00048.html");
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

  if ((res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.7~54.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"autofs-debuginfo", rpm:"autofs-debuginfo~5.0.7~54.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
