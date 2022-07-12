###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for lftp CESA-2010:0585 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-August/016860.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880589");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2251");
  script_name("CentOS Update for lftp CESA-2010:0585 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lftp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"lftp on CentOS 5");
  script_tag(name:"insight", value:"LFTP is a sophisticated file transfer program for the FTP and HTTP
  protocols. Like Bash, it has job control and uses the Readline library for
  input. It has bookmarks, built-in mirroring, and can transfer several files
  in parallel. It is designed with reliability in mind.

  It was discovered that lftp trusted the file name provided in the
  Content-Disposition HTTP header. A malicious HTTP server could use this
  flaw to write or overwrite files in the current working directory of a
  victim running lftp, by sending a different file from what the victim
  requested. (CVE-2010-2251)

  To correct this flaw, the following changes were made to lftp: the
  'xfer:clobber' option now defaults to 'no', causing lftp to not overwrite
  existing files, and a new option, 'xfer:auto-rename', which defaults to
  'no', has been introduced to control whether lftp should use
  server-suggested file names. Refer to the 'Settings' section of the lftp(1)
  manual page for additional details on changing lftp settings.

  All lftp users should upgrade to this updated package, which contains a
  backported patch to correct this issue.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"lftp", rpm:"lftp~3.7.11~4.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
