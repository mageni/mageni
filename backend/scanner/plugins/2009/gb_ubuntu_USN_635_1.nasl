###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_635_1.nasl 7969 2017-12-01 09:23:16Z santu $
#
# Ubuntu Update for xine-lib vulnerabilities USN-635-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "Alin Rad Pop discovered an array index vulnerability in the SDP
  parser. If a user or automated system were tricked into opening a
  malicious RTSP stream, a remote attacker may be able to execute
  arbitrary code with the privileges of the user invoking the program.
  (CVE-2008-0073)

  Luigi Auriemma discovered that xine-lib did not properly check
  buffer sizes in the RTSP header-handling code. If xine-lib opened an
  RTSP stream with crafted SDP attributes, a remote attacker may be
  able to execute arbitrary code with the privileges of the user
  invoking the program. (CVE-2008-0225, CVE-2008-0238)
  
  Damian Frizza and Alfredo Ortega discovered that xine-lib did not
  properly validate FLAC tags. If a user or automated system were
  tricked into opening a crafted FLAC file, a remote attacker may be
  able to execute arbitrary code with the privileges of the user
  invoking the program. (CVE-2008-0486)
  
  It was discovered that the ASF demuxer in xine-lib did not properly
  check the length if the ASF header. If a user or automated system
  were tricked into opening a crafted ASF file, a remote attacker
  could cause a denial of service or possibly execute arbitrary code
  with the privileges of the user invoking the program. (CVE-2008-1110)
  
  It was discovered that the Matroska demuxer in xine-lib did not
  properly verify frame sizes. If xine-lib opened a crafted ASF file,
  a remote attacker could cause a denial of service or possibly
  execute arbitrary code with the privileges of the user invoking
  the program. (CVE-2008-1161)
  
  Luigi Auriemma discovered multiple integer overflows in xine-lib. If
  a user or automated system were tricked into opening a crafted FLV,
  MOV, RM, MVE, MKV or CAK file, a remote attacker may be able to
  execute arbitrary code with the privileges of the user invoking the
  program. (CVE-2008-1482)
  
  It was discovered that xine-lib did not properly validate its input
  when processing Speex file headers. If a user or automated system
  were tricked into opening a specially crafted Speex file, an
  attacker could create a denial of service or possibly execute
  arbitrary code as the user invoking the program. (CVE-2008-1686)
  
  Guido Landi discovered a stack-based buffer overflow in xine-lib
  when processing NSF files. If xine-lib opened a specially crafted
  NSF file with a long NSF title, an attacker could create a denial of
  service or possibly execute arbitrary code as the user invoking the
  program. (CVE-2008-1878)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-635-1";
tag_affected = "xine-lib vulnerabilities on Ubuntu 6.06 LTS ,
  Ubuntu 7.04 ,
  Ubuntu 7.10 ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-635-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.304619");
  script_version("$Revision: 7969 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 10:23:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0073", "CVE-2008-0225", "CVE-2008-0238", "CVE-2008-0486", "CVE-2008-1110", "CVE-2008-1161", "CVE-2008-1482", "CVE-2008-1686", "CVE-2008-1878");
  script_name( "Ubuntu Update for xine-lib vulnerabilities USN-635-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxine-dev", ver:"1.1.1+ubuntu2-7.9", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine-main1", ver:"1.1.1+ubuntu2-7.9", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"libxine-dev", ver:"1.1.4-2ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-dbg", ver:"1.1.4-2ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-kde", ver:"1.1.4-2ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1", ver:"1.1.4-2ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-console", ver:"1.1.4-2ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-ffmpeg", ver:"1.1.4-2ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-gnome", ver:"1.1.4-2ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine-extracodecs", ver:"1.1.4-2ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine-main1", ver:"1.1.4-2ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-plugins", ver:"1.1.4-2ubuntu3.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libxine-dev", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-bin", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-console", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-dbg", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-misc-plugins", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-x", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-ffmpeg", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-gnome", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-doc", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-all-plugins", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-plugins", ver:"1.1.11.1-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"libxine1-dbg", ver:"1.1.7-1ubuntu1.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1", ver:"1.1.7-1ubuntu1.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-console", ver:"1.1.7-1ubuntu1.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-ffmpeg", ver:"1.1.7-1ubuntu1.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-gnome", ver:"1.1.7-1ubuntu1.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine-dev", ver:"1.1.7-1ubuntu1.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-doc", ver:"1.1.7-1ubuntu1.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libxine1-plugins", ver:"1.1.7-1ubuntu1.3", rls:"UBUNTU7.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
