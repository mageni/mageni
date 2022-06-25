###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for cups RHSA-2011:1635-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00014.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870611");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:33:58 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-2896");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for cups RHSA-2011:1635-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"cups on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX operating systems.

  A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch (LZW)
  decompression algorithm implementation used by the CUPS GIF image format
  reader. An attacker could create a malicious GIF image file that, when
  printed, could possibly cause CUPS to crash or, potentially, execute
  arbitrary code with the privileges of the 'lp' user. (CVE-2011-2896)

  These updated cups packages also provide fixes for the following bugs:

  * Previously CUPS was not correctly handling the language setting
  LANG=en_US.ASCII. As a consequence lpadmin, lpstat and lpinfo binaries were
  not displaying any output when the LANG=en_US.ASCII environment variable
  was used. As a result of this update the problem is fixed and the expected
  output is now displayed. (BZ#681836)

  * Previously the scheduler did not check for empty values of several
  configuration directives. As a consequence it was possible for the CUPS
  daemon (cupsd) to crash when a configuration file contained certain empty
  values. With this update the problem is fixed and cupsd no longer crashes
  when reading such a configuration file. (BZ#706673)

  * Previously when printing to a raw print queue, when using certain printer
  models, CUPS was incorrectly sending SNMP queries. As a consequence there
  was a noticeable 4-second delay between queueing the job and the start of
  printing. With this update the problem is fixed and CUPS no longer tries to
  collect SNMP supply and status information for raw print queues.
  (BZ#709896)

  * Previously when using the BrowsePoll directive it could happen that the
  CUPS printer polling daemon (cups-polld) began polling before the network
  interfaces were set up after a system boot. CUPS was then caching the
  failed hostname lookup. As a consequence no printers were found and the
  error, 'Host name lookup failure', was logged. With this update the code
  that re-initializes the resolver after failure in cups-polld is fixed and
  as a result CUPS will obtain the correct network settings to use in printer
  discovery. (BZ#712430)

  * The MaxJobs directive controls the maximum number of print jobs that are
  kept in memory. Previously, once the number of jobs reached the limit, the
  CUPS system failed to automatically purge the data file associated with the
  oldest completed job from the system in order to make room for a new print
   ...

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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.4.2~44.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.4.2~44.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.4.2~44.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.4.2~44.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-lpd", rpm:"cups-lpd~1.4.2~44.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
