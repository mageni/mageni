###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for ffmpeg MDVSA-2011:060 (ffmpeg)
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-04/msg00002.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831358");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-04-06 16:20:31 +0200 (Wed, 06 Apr 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4632", "CVE-2009-4633", "CVE-2009-4634", "CVE-2009-4635", "CVE-2009-4639", "CVE-2009-4640", "CVE-2010-3429", "CVE-2010-4704");
  script_name("Mandriva Update for ffmpeg MDVSA-2011:060 (ffmpeg)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2009\.0)");
  script_tag(name:"affected", value:"ffmpeg on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been identified and fixed in ffmpeg:

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

  The av_rescale_rnd function in the AVI demuxer in FFmpeg 0.5 allows
  remote attackers to cause a denial of service (crash) via a crafted
  AVI file that triggers a divide-by-zero error. (CVE-2009-4639)

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

  And several additional vulnerabilities originally discovered by Google
  Chrome developers were also fixed with this advisory.

  Package ...

  Description truncated, please see the referenced URL(s) for more information.");
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformats52", rpm:"libavformats52~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil49", rpm:"libavutil49~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libffmpeg51", rpm:"libffmpeg51~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscaler0", rpm:"libswscaler0~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avformats52", rpm:"lib64avformats52~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avutil49", rpm:"lib64avutil49~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ffmpeg51", rpm:"lib64ffmpeg51~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64swscaler0", rpm:"lib64swscaler0~0.4.9~3.pre1.14161.1.4mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformats52", rpm:"libavformats52~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil49", rpm:"libavutil49~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libffmpeg51", rpm:"libffmpeg51~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscaler0", rpm:"libswscaler0~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avformats52", rpm:"lib64avformats52~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avutil49", rpm:"lib64avutil49~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ffmpeg51", rpm:"lib64ffmpeg51~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64swscaler0", rpm:"lib64swscaler0~0.4.9~3.pre1.14161.1.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
