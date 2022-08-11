###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for ffmpeg MDVSA-2012:076 (ffmpeg)
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
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:076");
  script_oid("1.3.6.1.4.1.25623.1.0.831563");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-08-03 09:48:24 +0530 (Fri, 03 Aug 2012)");
  script_cve_id("CVE-2011-3362", "CVE-2011-3504", "CVE-2011-3973", "CVE-2011-3974",
                "CVE-2011-3892", "CVE-2011-3893", "CVE-2011-3895", "CVE-2011-4351",
                "CVE-2011-4352", "CVE-2011-4353", "CVE-2011-4364", "CVE-2011-4579",
                "CVE-2011-3929", "CVE-2011-3936", "CVE-2011-3937", "CVE-2011-3940",
                "CVE-2011-3945", "CVE-2011-3947", "CVE-2012-0853", "CVE-2012-0858");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandriva Update for ffmpeg MDVSA-2012:076 (ffmpeg)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"ffmpeg on Mandriva Linux 2011.0");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in ffmpeg:

  The Matroska format decoder in FFmpeg does not properly allocate
  memory, which allows remote attackers to execute arbitrary code via
  a crafted file (CVE-2011-3362, CVE-2011-3504).

  cavsdec.c in libavcodec in FFmpeg allows remote attackers to cause
  a denial of service (incorrect write operation and application
  crash) via an invalid bitstream in a Chinese AVS video (aka CAVS)
  file, related to the decode_residual_block, check_for_slice,
  and cavs_decode_frame functions, a different vulnerability than
  CVE-2011-3362 (CVE-2011-3973).

  Double free vulnerability in the Theora decoder in FFmpeg allows remote
  attackers to cause a denial of service or possibly have unspecified
  other impact via a crafted stream (CVE-2011-3892).

  FFmpeg does not properly implement the MKV and Vorbis media
  handlers, which allows remote attackers to cause a denial of service
  (out-of-bounds read) via unspecified vectors (CVE-2011-3893).

  Heap-based buffer overflow in the Vorbis decoder in FFmpeg allows
  remote attackers to cause a denial of service or possibly have
  unspecified other impact via a crafted stream (CVE-2011-3895).

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

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavfilter1", rpm:"libavfilter1~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavformats52", rpm:"libavformats52~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libavutil50", rpm:"libavutil50~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libffmpeg52", rpm:"libffmpeg52~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpostproc51", rpm:"libpostproc51~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libswscaler0", rpm:"libswscaler0~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avfilter1", rpm:"lib64avfilter1~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avformats52", rpm:"lib64avformats52~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64avutil50", rpm:"lib64avutil50~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ffmpeg52", rpm:"lib64ffmpeg52~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64postproc51", rpm:"lib64postproc51~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64swscaler0", rpm:"lib64swscaler0~0.7.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
