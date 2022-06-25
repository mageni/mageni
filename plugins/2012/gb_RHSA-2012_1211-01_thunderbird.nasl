###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for thunderbird RHSA-2012:1211-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-August/msg00030.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870817");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-08-30 10:35:23 +0530 (Thu, 30 Aug 2012)");
  script_cve_id("CVE-2012-1970", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974",
                "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957",
                "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961",
                "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3966",
                "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970",
                "CVE-2012-3972", "CVE-2012-3978", "CVE-2012-3980");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for thunderbird RHSA-2012:1211-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"thunderbird on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed content. Malicious
  content could cause Thunderbird to crash or, potentially, execute arbitrary
  code with the privileges of the user running Thunderbird. (CVE-2012-1970,
  CVE-2012-1972, CVE-2012-1973, CVE-2012-1974, CVE-2012-1975, CVE-2012-1976,
  CVE-2012-3956, CVE-2012-3957, CVE-2012-3958, CVE-2012-3959, CVE-2012-3960,
  CVE-2012-3961, CVE-2012-3962, CVE-2012-3963, CVE-2012-3964)

  Content containing a malicious Scalable Vector Graphics (SVG) image file
  could cause Thunderbird to crash or, potentially, execute arbitrary code
  with the privileges of the user running Thunderbird. (CVE-2012-3969,
  CVE-2012-3970)

  Two flaws were found in the way Thunderbird rendered certain images using
  WebGL. Malicious content could cause Thunderbird to crash or, under certain
  conditions, possibly execute arbitrary code with the privileges of the user
  running Thunderbird. (CVE-2012-3967, CVE-2012-3968)

  A flaw was found in the way Thunderbird decoded embedded bitmap images in
  Icon Format (ICO) files. Content containing a malicious ICO file could
  cause Thunderbird to crash or, under certain conditions, possibly execute
  arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2012-3966)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Gary Kwong, Christian Holler, Jesse Ruderman, John
  Schoenick, Vladimir Vukicevic, Daniel Holbert, Abhishek Arya, Frederic
  Hoguin, miaubiz, Arthur Gerkis, Nicolas Gregoire, moz_bug_r_a4, and Colby
  Russell as the original reporters of these issues.

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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~10.0.7~1.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~10.0.7~1.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
