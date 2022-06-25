###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for blender MDVSA-2011:114 (blender)
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-07/msg00003.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831427");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-07-22 14:44:51 +0200 (Fri, 22 Jul 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4632", "CVE-2009-4633", "CVE-2009-4634", "CVE-2009-4635", "CVE-2009-4636", "CVE-2009-4640", "CVE-2010-3429", "CVE-2010-4704", "CVE-2011-0722", "CVE-2011-0723");
  script_name("Mandriva Update for blender MDVSA-2011:114 (blender)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'blender'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2010\.1");
  script_tag(name:"affected", value:"blender on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been identified and fixed in blender:

  oggparsevorbis.c in FFmpeg 0.5 does not properly perform certain
  pointer arithmetic, which might allow remote attackers to obtain
  sensitive memory contents and cause a denial of service via a crafted
  file that triggers an out-of-bounds read. (CVE-2009-4632)

  vorbis_dec.c in FFmpeg 0.5 uses an assignment operator when a
  comparison operator was intended, which might allow remote attackers
  to cause a denial of service and possibly execute arbitrary code via
  a crafted file that modifies a loop counter and triggers a heap-based
  buffer overflow. (CVE-2009-4633)

  Multiple integer underflows in FFmpeg 0.5 allow remote attackers to
  cause a denial of service and possibly execute arbitrary code via a
  crafted file that (1) bypasses a validation check in vorbis_dec.c
  and triggers a wraparound of the stack pointer, or (2) access a
  pointer from out-of-bounds memory in mov.c, related to an elst tag
  that appears before a tag that creates a stream. (CVE-2009-4634)

  FFmpeg 0.5 allows remote attackers to cause a denial of service and
  possibly execute arbitrary code via a crafted MOV container with
  improperly ordered tags that cause (1) mov.c and (2) utils.c to use
  inconsistent codec types and identifiers, which causes the mp3 decoder
  to process a pointer for a video structure, leading to a stack-based
  buffer overflow. (CVE-2009-4635)

  FFmpeg 0.5 allows remote attackers to cause a denial of service (hang)
  via a crafted file that triggers an infinite loop. (CVE-2009-4636)

  Array index error in vorbis_dec.c in FFmpeg 0.5 allows remote
  attackers to cause a denial of service and possibly execute arbitrary
  code via a crafted Vorbis file that triggers an out-of-bounds
  read. (CVE-2009-4640)

  flicvideo.c in libavcodec 0.6 and earlier in FFmpeg, as used in MPlayer
  and other products, allows remote attackers to execute arbitrary code
  via a crafted flic file, related to an arbitrary offset dereference
  vulnerability. (CVE-2010-3429)

  libavcodec/vorbis_dec.c in the Vorbis decoder in FFmpeg 0.6.1
  and earlier allows remote attackers to cause a denial of service
  (application crash) via a crafted .ogg file, related to the
  vorbis_floor0_decode function. (CVE-2010-4704)

  Fix heap corruption crashes (CVE-2011-0722)

  Fix invalid reads in VC-1 decoding (CVE-2011-0723)

  The updated packages have been patched to correct these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"blender", rpm:"blender~2.49b~4.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
