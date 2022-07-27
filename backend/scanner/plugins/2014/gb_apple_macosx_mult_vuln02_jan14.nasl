###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln02_jan14.nasl 30092 2014-01-20 19:13:47Z Jan$
#
# Apple Mac OS X Multiple Vulnerabilities - 02 Jan14
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804061");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2013-0982", "CVE-2013-0983", "CVE-2012-5519", "CVE-2013-0985",
                "CVE-2013-0989", "CVE-2012-4929", "CVE-2011-1945", "CVE-2011-3207",
                "CVE-2011-3210", "CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576",
                "CVE-2011-4577", "CVE-2011-4619", "CVE-2012-0050", "CVE-2012-2110",
                "CVE-2012-2131", "CVE-2012-2333", "CVE-2013-0986", "CVE-2013-0987",
                "CVE-2013-0988", "CVE-2013-0990", "CVE-2013-0975", "CVE-2013-1024");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-01-20 19:13:47 +0530 (Mon, 20 Jan 2014)");
  script_name("Apple Mac OS X Multiple Vulnerabilities - 02 Jan14");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Permanent cookies were saved after quitting Safari, even when Private
    Browsing was enabled.

  - An unbounded stack allocation issue existed in the handling of text glyphs.

  - A privilege escalation issue existed in the handling of CUPS configuration
    via the CUPS web interface.

  - A local user who is not an administrator may disable FileVault using the
    command-line.

  - A buffer overflow existed in the handling of MP3 files.

  - A buffer overflow existed in the handling of FPX files.

  - A memory corruption issue existed in the handling of QTIF files.

  - A buffer overflow existed in the handling of 'enof' atoms.

  - Multiple errors in OpenSSL.

  - There were known attacks on the confidentiality of TLS 1.0 when compression
    was enabled.

  - An uninitialized memory access issue existed in the handling of text tracks.

  - A buffer overflow existed in the handling of PICT images.

  - If SMB file sharing is enabled, an authenticated user may be able to write
    files outside the shared directory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to, execute arbitrary code or cause a denial of service or
  lead to an unexpected application termination.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.8 to 10.8.3,
  10.7 to 10.7.5 and 10.6.8");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version 10.8.4
  or later or apply appropriate security update for 10.7 and 10.6 versions. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5784");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.[6-8]");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.[6-8]"){
  exit(0);
}

if(osVer == "10.7.5")
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }
  if(version_is_less(version:buildVer, test_version:"11G1032"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

if(osVer =~ "^10\.8")
{
  if(version_is_less(version:osVer, test_version:"10.8.4")){
    fix = "Upgrade to 10.8.4 or later";
  }
}

else if(osVer == "10.6.8")
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }

  if(version_is_less(version:buildVer, test_version:"10K1115"))
  {
    fix = "Apply patch from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);